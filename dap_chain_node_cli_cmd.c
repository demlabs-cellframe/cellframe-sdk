/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>

#include "iputils/iputils.h"

#include "uthash.h"
#include "utlist.h"

#include "dap_string.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_string.h"
#include "dap_chain_cert.h"
#include "dap_chain_wallet.h"
#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_remote.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_net_srv.h"

#include "dap_chain_datum.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_utxo.h"
#include "dap_chain_mempool.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net_pkt.h"

#define LOG_TAG "chain_node_cli_cmd"

/**
 * Find in base addr by alias
 *
 * return addr, NULL if not found
 */
dap_chain_node_addr_t* dap_chain_node_addr_get_by_alias(const char *a_alias)
{
    dap_chain_node_addr_t *l_addr = NULL;
    if(!a_alias)
        return NULL;
    const char *a_key = a_alias;
    size_t l_addr_size = 0;
    l_addr = (dap_chain_node_addr_t*) (void*) dap_chain_global_db_gr_get(a_key, &l_addr_size, GROUP_GLOBAL_ALIAS);
    if(l_addr_size != sizeof(dap_chain_node_addr_t)) {
//        l_addr = DAP_NEW_Z(dap_chain_node_addr_t);
//        if(hex2bin((char*) l_addr, (const unsigned char *) addr_str, sizeof(dap_chain_node_addr_t) * 2) == -1) {
        DAP_DELETE(l_addr);
//            l_addr = NULL;
//        }
    }
//    DAP_DELETE(addr_str);
    return l_addr;
}

/**
 * Find in base alias by addr
 *
 * return list of addr, NULL if not found
 */
static dap_list_t* get_aliases_by_name(dap_chain_node_addr_t *a_addr)
{
    if(!a_addr)
        return NULL;
    dap_list_t *list_aliases = NULL;
    size_t data_size = 0;
    // read all aliases
    dap_global_db_obj_t **objs = dap_chain_global_db_gr_load(GROUP_GLOBAL_ALIAS, &data_size);
    if(!objs || !data_size)
        return NULL;
    for(size_t i = 0; i < data_size; i++) {
        //dap_chain_node_addr_t addr_i;
        dap_global_db_obj_t *obj = objs[i];
        if(!obj)
            break;
        dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t*) (void*) obj->value;
        if(l_addr && obj->value_len == sizeof(dap_chain_node_addr_t) && a_addr->uint64 == l_addr->uint64) {
            list_aliases = dap_list_prepend(list_aliases, strdup(obj->key));
        }
        /*        char *addr_str = obj->value;
         if(addr_str && strlen(addr_str) == sizeof(dap_chain_node_addr_t) * 2) {
         //addr_i = DAP_NEW_Z(dap_chain_node_addr_t);
         if(hex2bin((char*) &addr_i, (const unsigned char *) addr_str, sizeof(dap_chain_node_addr_t) * 2) == -1) {
         continue;
         }
         if(a_addr->uint64 == addr_i.uint64) {
         list_aliases = dap_list_prepend(list_aliases, strdup(obj->key));
         }
         }*/
    }
    dap_chain_global_db_objs_delete(objs);
    return list_aliases;
}

static dap_chain_node_addr_t* com_global_db_get_addr(dap_chain_node_info_t *node_info,
        dap_chain_node_addr_t *addr, const char *alias_str)
{
    dap_chain_node_addr_t *address = NULL;
    if(alias_str && !addr->uint64) {
        address = dap_chain_node_addr_get_by_alias(alias_str);
    }
    if(addr->uint64) {
        address = DAP_NEW(dap_chain_node_addr_t);
        address->uint64 = addr->uint64;
    }
    return address;
}


/**
 * Read node from base
 */
static dap_chain_node_info_t* dap_chain_node_info_read_and_reply(dap_chain_node_addr_t *address, char **str_reply)
{
    char *l_key = dap_chain_node_addr_to_hash_str(address);
    if(!l_key)
    {
        dap_chain_node_cli_set_reply_text(str_reply, "can't calculate hash of addr");
        return NULL;
    }
    size_t node_info_size = 0;
    dap_chain_node_info_t *node_info;
    // read node
    node_info = (dap_chain_node_info_t *) dap_chain_global_db_gr_get(l_key, &node_info_size, GROUP_GLOBAL_ADDRS_LEASED);

    if(!node_info) {
        dap_chain_node_cli_set_reply_text(str_reply, "node not found in base");
        DAP_DELETE(l_key);
        return NULL;
    }
    size_t node_info_size_must_be = dap_chain_node_info_get_size(node_info);
    if(node_info_size_must_be != node_info_size) {
        dap_chain_node_cli_set_reply_text(str_reply, "node has bad size in base=%u (must be %u)", node_info_size,
                node_info_size_must_be);
        DAP_DELETE(node_info);
        DAP_DELETE(l_key);
        return NULL;
    }

//    dap_chain_node_info_t *node_info = dap_chain_node_info_deserialize(str, (str) ? strlen(str) : 0);
//    if(!node_info) {
//        set_reply_text(str_reply, "node has invalid format in base");
//    }
//    DAP_DELETE(str);
    DAP_DELETE(l_key);
    return node_info;
}

/**
 * Save node to base
 */
static bool dap_chain_node_info_save_and_reply(dap_chain_node_info_t *node_info, char **str_reply)
{
    if(!node_info || !node_info->hdr.address.uint64) {
        dap_chain_node_cli_set_reply_text(str_reply, "node addr not found");
        return false;
    }
    char *a_key = dap_chain_node_addr_to_hash_str(&node_info->hdr.address);
    if(!a_key)
    {
        dap_chain_node_cli_set_reply_text(str_reply, "can't calculate hash for addr");
        return NULL;
    }
    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t node_info_size = dap_chain_node_info_get_size(node_info);
    bool res = dap_chain_global_db_gr_set(a_key, (const uint8_t *) node_info, node_info_size, GROUP_GLOBAL_ADDRS_LEASED);
    DAP_DELETE(a_key);
    //DAP_DELETE(a_value);
    return res;
}




/**
 * Handler of command 'global_db node add'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_add(dap_chain_node_info_t *a_node_info, const char *alias_str,
        const char *cell_str, const char *ipv4_str, const char *ipv6_str, char **str_reply)
{

    if(!a_node_info->hdr.address.uint64) {
        dap_chain_node_cli_set_reply_text(str_reply, "not found -addr parameter");
        return -1;
    }
    if(!cell_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "not found -cell parameter");
        return -1;
    }
    if(!ipv4_str && !ipv6_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "not found -ipv4 or -ipv6 parameter");
        return -1;
    }
    else {
        if(ipv4_str)
            inet_pton(AF_INET, ipv4_str, &(a_node_info->hdr.ext_addr_v4));
        if(ipv6_str)
            inet_pton(AF_INET6, ipv6_str, &(a_node_info->hdr.ext_addr_v6));
    }
    // check match addr to cell or no
    /*dap_chain_node_addr_t *addr = dap_chain_node_gen_addr(&node_info->hdr.cell_id);
     if(!dap_chain_node_check_addr(&node_info->hdr.address, &node_info->hdr.cell_id)) {
     set_reply_text(str_reply, "cell does not match addr");
     return -1;
     }*/
    if(alias_str) {
        // add alias
        if(!dap_chain_node_alias_register(alias_str, &a_node_info->hdr.address)) {
            log_it(L_WARNING, "can't save alias %s", alias_str);
            dap_chain_node_cli_set_reply_text(str_reply, "alias '%s' can't be mapped to addr=0x%lld",
                    alias_str, a_node_info->hdr.address.uint64);
            return -1;
        }
    }

    // write to base
    bool res = dap_chain_node_info_save_and_reply(a_node_info, str_reply);
    if(res)
        dap_chain_node_cli_set_reply_text(str_reply, "node added");
    else
        return -1;
    if(res)
        return 0;
    return -1;
}

/**
 * Handler of command 'global_db node add'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_del(dap_chain_node_info_t *node_info, const char *alias_str, char **str_reply)
{
    if(!node_info->hdr.address.uint64 && !alias_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "addr not found");
        return -1;
    }
    // check, current node have this addr or no
    uint64_t l_cur_addr = dap_db_get_cur_node_addr();
    if(l_cur_addr && l_cur_addr == node_info->hdr.address.uint64) {
        dap_chain_node_cli_set_reply_text(str_reply, "current node cannot be deleted");
        return -1;
    }

    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, &node_info->hdr.address, alias_str);
    if(!address) {
        dap_chain_node_cli_set_reply_text(str_reply, "alias not found");
        return -1;
    }
    char *a_key = dap_chain_node_addr_to_hash_str(address);
    if(a_key)
    {
        // delete node
        bool res = dap_chain_global_db_gr_del(a_key, GROUP_GLOBAL_ADDRS_LEASED);
        if(res) {
            // delete all aliases for node address
            {
                dap_list_t *list_aliases = get_aliases_by_name(address);
                dap_list_t *list = list_aliases;
                while(list)
                {
                    const char *alias = (const char *) list->data;
                    dap_chain_node_alias_delete(alias);
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
 * Handler of command 'global_db node link'
 *
 * cmd 'add' or 'del'
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_link(dap_chain_node_info_t *node_info, const char *cmd, const char *alias_str,
        dap_chain_node_addr_t *link, char **str_reply)
{
    if(!node_info->hdr.address.uint64 && !alias_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "addr not found");
        return -1;
    }
    if(!link->uint64) {
        dap_chain_node_cli_set_reply_text(str_reply, "link not found");
        return -1;
    }
    // TODO check the presence of link in the node base
    if(0) {
        dap_chain_node_cli_set_reply_text(str_reply, "node 0x%016llx not found in base", link->uint64);
        return -1;
    }

    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, &node_info->hdr.address, alias_str);
    if(!address) {
        dap_chain_node_cli_set_reply_text(str_reply, "alias not found");
        return -1;
    }


    dap_chain_node_info_t * l_node_info_read = dap_chain_node_info_read_and_reply(address, str_reply);
    size_t l_node_info_read_size = dap_chain_node_info_get_size( l_node_info_read);
    if(! l_node_info_read)
        return -1;

    int cmd_int = 0;
    if(!strcmp(cmd, "add"))
        cmd_int = 1;
    else if(!strcmp(cmd, "del"))
        cmd_int = 2;

    // find link in node_info_read
    int index_link = -1;
    for(size_t i = 0; i <  l_node_info_read->hdr.links_number; i++) {
        if( l_node_info_read->links[i].uint64 == link->uint64) {
            // link already present
            index_link = (int) i;
            break;
        }
    }
    bool res_successful = false; // is successful whether add/del
    // add link
    if(cmd_int == 1) {
        if(index_link == -1) {
            l_node_info_read = DAP_REALLOC ( l_node_info_read,l_node_info_read_size += sizeof (*link) );
            memcpy(&( l_node_info_read->links[ l_node_info_read->hdr.links_number]), link, sizeof(dap_chain_node_addr_t));
             l_node_info_read->hdr.links_number++;
            res_successful = true;
        }
    }
    // delete link
    else if(cmd_int == 2) {
        // move link list to one item prev
        if(index_link >= 0) {
            for(unsigned int j = (unsigned int) index_link; j < ( l_node_info_read->hdr.links_number - 1); j++) {
                memcpy(&( l_node_info_read->links[j]), &( l_node_info_read->links[j + 1]), sizeof(dap_chain_node_addr_t));
            }
            l_node_info_read->hdr.links_number--;
            res_successful = true;
            l_node_info_read = DAP_REALLOC ( l_node_info_read,l_node_info_read_size -= sizeof (*link) );
        }
    }
    // save edited node_info
    if(res_successful) {
        bool res = dap_chain_node_info_save_and_reply( l_node_info_read, str_reply);
        if(res) {
            res_successful = true;
            if(cmd_int == 1)
                dap_chain_node_cli_set_reply_text(str_reply, "link added");
            if(cmd_int == 2)
                dap_chain_node_cli_set_reply_text(str_reply, "link deleted");
        }
        else {
            res_successful = false;
        }
    }
    else {
        if(cmd_int == 1) {
            if(index_link >= 0)
                dap_chain_node_cli_set_reply_text(str_reply, "link not added because it is already present");
            else
                dap_chain_node_cli_set_reply_text(str_reply, "link not added");
        }
        if(cmd_int == 2) {
            if(index_link == -1)
                dap_chain_node_cli_set_reply_text(str_reply, "link not deleted because not found");
            else
                dap_chain_node_cli_set_reply_text(str_reply, "link not deleted");
        }
    }

    DAP_DELETE(address);
    DAP_DELETE( l_node_info_read);
    if(res_successful)
        return 0;
    return -1;
}

/**
 * Handler of command 'global_db node dump'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_dump(dap_chain_node_info_t *a_node_info, const char *alias_str, char **str_reply)
{
    size_t l_nodes_count = 1;
    //bool show_all_addr = false;
    dap_global_db_obj_t **l_objs = NULL;
    if(!a_node_info->hdr.address.uint64 && !alias_str) {
        //set_reply_text(str_reply, "addr not found");
        //return -1;
        //show_all_addr = true;
        // read all nodes
        dap_chain_node_info_t *node_info;
        // read all node
        l_objs = dap_chain_global_db_gr_load(GROUP_GLOBAL_ADDRS_LEASED, &l_nodes_count);
        /*for(size_t i = 0; i < l_nodes_count; i++) {
         dap_global_db_obj_t *l_obj = l_objs[i];
         dap_chain_node_info_t *node_info = (dap_chain_node_info_t *) l_obj->value;
         node_info->

         }*/
        if(!l_nodes_count || !l_objs) {
            dap_chain_node_cli_set_reply_text(str_reply, "nodes not found");
            return -1;
        }
    }
    size_t i;
    dap_string_t *l_string_reply = dap_string_new(NULL);
    for(i = 0; i < l_nodes_count; i++) {
        dap_chain_node_info_t *node_info = (!l_objs) ? a_node_info : (dap_chain_node_info_t *) l_objs[i]->value;
        // find addr by alias or addr_str
        dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, &node_info->hdr.address, alias_str);
        if(!address) {
            dap_chain_node_cli_set_reply_text(str_reply, "alias not found");
            break;
        }
        // read node
        dap_chain_node_info_t *node_info_read = dap_chain_node_info_read_and_reply(address, str_reply);
        if(!node_info_read) {
            DAP_DELETE(address);
            break;
        }

        int hostlen = 128;
        char host4[hostlen];
        char host6[hostlen];
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = node_info_read->hdr.ext_addr_v4 };
        const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, hostlen);

        struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = node_info_read->hdr.ext_addr_v6 };
        const char* str_ip6 = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host6, hostlen);

        // get aliases in form of string
        dap_string_t *aliases_string = dap_string_new(NULL);
        dap_list_t *list_aliases = get_aliases_by_name(address);
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
            dap_string_append_printf(links_string, "\nlink%02d address : 0x%016llx", i, link_addr.uint64);
        }

        if(i)
            dap_string_append_printf(l_string_reply, "\n");
        // set short reply with node param
        if(l_objs)
            dap_string_append_printf(l_string_reply,
                    "node address 0x%016llx\tcell 0x%016llx\tipv4 %s\tnumber of links %u",
                    node_info_read->hdr.address.uint64, node_info_read->hdr.cell_id.uint64,
                    str_ip4, node_info_read->hdr.links_number);
        else
            // set full reply with node param
            dap_string_append_printf(l_string_reply,
                    "node address 0x%016llx\ncell 0x%016llx%s\nipv4 %s\nipv6 %s\nlinks %u%s",
                    node_info_read->hdr.address.uint64, node_info_read->hdr.cell_id.uint64, aliases_string->str,
                    str_ip4, str_ip6,
                    node_info_read->hdr.links_number, links_string->str);
        dap_string_free(aliases_string, true);
        dap_string_free(links_string, true);

        DAP_DELETE(address);
        DAP_DELETE(node_info_read);
    }
    if(i == l_nodes_count) {
        // set full reply with node param
        dap_chain_node_cli_set_reply_text(str_reply, l_string_reply->str);
    }
    dap_string_free(l_string_reply, true);
    if(i < l_nodes_count)
        return -1;
    else
        return 0;
}

/**
 * Handler of command 'global_db node cur_node_get'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_cur_node_get(char **a_str_reply)
{
    // get cur node addr
    uint64_t l_addr = dap_db_get_cur_node_addr();
    if(l_addr) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "address for current node is 0x%llu", l_addr);
        return 0;
    }
    dap_chain_node_cli_set_reply_text(a_str_reply, "address for node has not been set.");
    return -1;
}

/**
 * Handler of command 'global_db node cur_node_set'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_cur_node_set(dap_chain_node_info_t *a_node_info, const char *a_alias_str, char **a_str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !a_alias_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "addr not found");
        return -1;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_address = com_global_db_get_addr(a_node_info, &a_node_info->hdr.address, a_alias_str);
    if(!l_address) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "alias not found");
        return -1;
    }
    // read node
    dap_chain_node_info_t *l_node_info_read = dap_chain_node_info_read_and_reply(l_address, a_str_reply);
    if(!l_node_info_read) {
        DAP_DELETE(l_address);
        return -1;
    }
    // set cur node addr
    if(dap_db_set_cur_node_addr(l_node_info_read->hdr.address.uint64)) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "new address for current node has been set");
        return 0;
    }
    dap_chain_node_cli_set_reply_text(a_str_reply, "new address for current node has not been set");
    return -1;
}

/**
 * Handler of command 'global_db node remote_set'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_node_request_addr(dap_chain_node_info_t *a_node_info, const char *a_alias_str, char **a_str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !a_alias_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "addr not found");
        DAP_DELETE(a_node_info);
        return -1;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_address = com_global_db_get_addr(a_node_info, &a_node_info->hdr.address, a_alias_str);
    if(!l_address) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "alias not found");
        DAP_DELETE(a_node_info);
        return -1;
    }
    // read node
    dap_chain_node_info_t *l_node_info_read = dap_chain_node_info_read_and_reply(l_address, a_str_reply);
    if(!l_node_info_read) {
        DAP_DELETE(l_address);
        DAP_DELETE(a_node_info);
        return -1;
    }

    dap_chain_node_info_t *l_node_info = dap_chain_node_info_read_and_reply(l_address, a_str_reply);
    if(!l_node_info) {
        DAP_DELETE(a_node_info);
        return -1;
    }
    // start connect
    dap_chain_node_client_t *client = dap_chain_node_client_connect(l_node_info);
    if(!client) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "can't connect");
        DAP_DELETE(l_node_info);
        return -1;
    }
    // wait connected
    int timeout_ms = 15000; //15 sec = 15000 ms
    int res = dap_chain_node_client_wait(client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
    if(res != 1) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "no response from node");
        // clean client struct
        dap_chain_node_client_close(client);
        DAP_DELETE(l_node_info);
        return -1;
    }

    // send request
    res = dap_chain_node_client_send_ch_pkt(client, dap_stream_ch_chain_net_get_id(),
    DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE_REQUEST,NULL,0);
    if(res != 1) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "no request sent");
        // clean client struct
        dap_chain_node_client_close(client);
        DAP_DELETE(l_node_info);
        return -1;
    }

    // wait for finishing of request
    timeout_ms = 120000; // 2 min = 120 sec = 120 000 ms
    res = dap_chain_node_client_wait(client, NODE_CLIENT_STATE_GET_NODE_ADDR, timeout_ms);
    DAP_DELETE(l_node_info);
    dap_client_disconnect(client->client);
    dap_chain_node_client_close(client);
    switch (res) {
    case 0:
        dap_chain_node_cli_set_reply_text(a_str_reply, "timeout");
        return -1;
    case 1: {
        uint64_t addr = dap_db_get_cur_node_addr();
        dap_chain_node_cli_set_reply_text(a_str_reply, "new address for remote node has been set 0x%x", addr);

    }
        return 0;
    default:
        dap_chain_node_cli_set_reply_text(a_str_reply, "error");
        return -1;
    }
}

/**
 * global_db command
 *
 * return 0 OK, -1 Err
 */
int com_global_db(int a_argc, const char ** a_argv, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_LINK, CMD_DUMP, CMD_CUR_NODE_GET, CMD_CUR_NODE_SET, CMD_CUR_NODE_SET_FROM_REMOTE
    };
    //printf("com_global_db\n");
    int arg_index = 1;
    // find 'node' as first parameter only
    arg_index = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "node", NULL);
    if(!arg_index || a_argc < 3) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "parameters are not valid");
        return -1;
    }
    int arg_index_n = ++arg_index;
    // find command (add, delete, etc) as second parameter only
    int cmd_num = CMD_NONE;
    if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "add", NULL))
            != 0) {
        cmd_num = CMD_ADD;
    }
    else if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "del", NULL))
            != 0) {
        cmd_num = CMD_DEL;
    }
    else if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "link", NULL))
            != 0) {
        cmd_num = CMD_LINK;
    }
    else if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "dump", NULL))
            != 0) {
        cmd_num = CMD_DUMP;
    }
    else if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "cur_node_get", NULL)) != 0) {
        cmd_num = CMD_CUR_NODE_GET;
    }
    else if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "cur_node_set", NULL)) != 0) {
        cmd_num = CMD_CUR_NODE_SET;
    }
    else if((arg_index_n = dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "cur_node_set_from_remote",
    NULL)) != 0) {
        cmd_num = CMD_CUR_NODE_SET_FROM_REMOTE;
    }
    if(cmd_num == CMD_NONE) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
        return -1;
    }
    //arg_index = arg_index_n; // no need, they are already equal must be
    assert(arg_index == arg_index_n);
    arg_index++;
    const char *l_addr_str = NULL, *alias_str = NULL, *l_cell_str = NULL, *l_link_str = NULL;
    const char *ipv4_str = NULL, *ipv6_str = NULL;
    // find addr, alias
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-alias", &alias_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-cell", &l_cell_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-ipv4", &ipv4_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-ipv6", &ipv6_str);
    dap_chain_node_cli_find_option_val(a_argv, arg_index, a_argc, "-link", &l_link_str);

    // struct to write to the global db
    dap_chain_node_addr_t l_link={0};
    dap_chain_node_info_t *l_node_info;
    size_t l_node_info_size = sizeof (l_node_info->hdr)+sizeof(l_link);
    l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t,l_node_info_size);

    if(l_addr_str) {
        dap_digit_from_string(l_addr_str, l_node_info->hdr.address.raw, sizeof(l_node_info->hdr.address.raw) );
    }
    if(l_cell_str) {
        dap_digit_from_string(l_cell_str, l_node_info->hdr.cell_id.raw, sizeof(l_node_info->hdr.cell_id.raw)); //DAP_CHAIN_CELL_ID_SIZE);
    }
    if(l_link_str) {
        dap_digit_from_string(l_link_str, l_link.raw, sizeof(l_link.raw));
    }

    switch (cmd_num)
    {
    // add new node to global_db
    case CMD_ADD:
        if(!arg_index || a_argc < 8) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameters");
            return -1;
        }
        // handler of command 'global_db node add'
        return com_global_db_add(l_node_info, alias_str, l_cell_str, ipv4_str, ipv6_str, a_str_reply);
        //break;

    case CMD_DEL:
        // handler of command 'global_db node del'
        return com_global_db_del(l_node_info, alias_str, a_str_reply);
    case CMD_LINK:
        if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "add", NULL))
            // handler of command 'global_db node link add -addr <node address> -link <node address>'
            return com_global_db_link(l_node_info, "add", alias_str, &l_link, a_str_reply);
        else if(dap_chain_node_cli_find_option_val(a_argv, arg_index, min(a_argc, arg_index + 1), "del", NULL))
            // handler of command 'global_db node link del -addr <node address> -link <node address>'
            return com_global_db_link(l_node_info, "del", alias_str, &l_link, a_str_reply);
        else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "command not recognize, supported format:\n"
                    "global_db node link <add|del] [-addr <node address>  | -alias <node alias>] -link <node address>");
            DAP_DELETE(l_node_info);
            return -1;
        }
    case CMD_DUMP:
        // handler of command 'global_db node dump'
        return com_global_db_dump(l_node_info, alias_str, a_str_reply);
    case CMD_CUR_NODE_GET:
        // handler of command 'global_db cur_node get'
        return com_global_db_cur_node_get(a_str_reply);
    case CMD_CUR_NODE_SET:
        // handler of command 'global_db cur_node set'
        return com_global_db_cur_node_set(l_node_info, alias_str, a_str_reply);
    case CMD_CUR_NODE_SET_FROM_REMOTE:
        // handler of command 'global_db node remote_set'
        return com_node_request_addr(l_node_info, alias_str, a_str_reply);

    default:
        dap_chain_node_cli_set_reply_text(a_str_reply, "command %s not recognized", a_argv[1]);
        return -1;
    }
    return -1;
}

/**
 * Node command
 */
int com_node(int argc, const char ** argv, char **str_reply)
{
    enum {
        CMD_NONE, CMD_ALIAS, CMD_HANDSHAKE, CMD_CONNECT
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *cmd_str = NULL;
// find  add parameter ('alias' or 'handshake')
    if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "handshake", NULL)) {
        cmd_num = CMD_HANDSHAKE;
    }
    else if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "connect", NULL)) {
        cmd_num = CMD_CONNECT;
    }
    else if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "alias", NULL)) {
        cmd_num = CMD_ALIAS;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        dap_chain_node_cli_set_reply_text(str_reply, "command %s not recognized", argv[1]);
        return -1;
    }
    dap_chain_node_addr_t address;
    memset(&address, 0, sizeof(dap_chain_node_addr_t));
    const char *addr_str = NULL, *alias_str = NULL;
    const char * l_net_str = NULL;
// find addr, alias
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-alias", &alias_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_str);

    dap_digit_from_string(addr_str, address.raw, sizeof(address.raw));

    if( l_net_str == NULL){
        dap_chain_node_cli_set_reply_text(str_reply, "No -net <net name> option in command %s", argv[1]);
        return -11;
    }

    dap_chain_net_t * l_net = dap_chain_net_by_name(l_net_str);

    if( l_net == NULL){
        dap_chain_node_cli_set_reply_text(str_reply, "%s: Can't find such network %s", argv[1], l_net_str);
        return -12;
    }

    switch (cmd_num)
        {
        // add alias
        case CMD_ALIAS:
            if(alias_str) {
                if(addr_str) {
                    // add alias
                    if(!dap_chain_node_alias_register(alias_str, &address))
                        log_it(L_WARNING, "can't save alias %s", alias_str);
                    else {
                        dap_chain_node_cli_set_reply_text(str_reply, "alias mapped successfully");
                    }
                }
                else {
                    dap_chain_node_cli_set_reply_text(str_reply, "alias can't be mapped because -addr is not found");
                    return -1;
                }
            }
            else {
                dap_chain_node_cli_set_reply_text(str_reply, "alias can't be mapped because -alias is not found");
                return -1;
            }

            break;
            // make connect
        case CMD_CONNECT: {
            // get address from alias if addr not defined
            if(alias_str && !address.uint64) {
                dap_chain_node_addr_t *address_tmp = dap_chain_node_addr_get_by_alias(alias_str);
                if(address_tmp) {
                    memcpy(&address, address_tmp, sizeof(address_tmp));
                    DAP_DELETE(address_tmp);
                }
                else {
                    dap_chain_node_cli_set_reply_text(str_reply, "no address found by alias");
                    return -1;
                }
            }
            if(!address.uint64) {
                dap_chain_node_cli_set_reply_text(str_reply, "addr not found");
                return -1;
            }

            // get cur node addr
            dap_chain_node_addr_t l_cur_node_addr;
            l_cur_node_addr.uint64 = dap_db_get_cur_node_addr();  //0x12345
            if(!l_cur_node_addr.uint64) {
                dap_chain_node_cli_set_reply_text(str_reply, "Current node has no address");
                return -1;
            }

            dap_chain_node_info_t *l_remote_node_info = dap_chain_node_info_read_and_reply(&address, str_reply);
            if(!l_remote_node_info) {
                return -1;
            }
            // start connect
            dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect(l_remote_node_info);
            if(!l_node_client) {
                dap_chain_node_cli_set_reply_text(str_reply, "can't connect");
                DAP_DELETE(l_remote_node_info);
                return -1;
            }
            // wait connected
            int timeout_ms = 15000; //15 sec = 15000 ms
            int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
            if(res != 1) {
                dap_chain_node_cli_set_reply_text(str_reply, "no response from node");
                // clean client struct
                dap_chain_node_client_close(l_node_client);
                DAP_DELETE(l_remote_node_info);
                return -1;
            }
            log_it(L_NOTICE, "Stream connection established, now lets sync all");
            dap_stream_ch_chain_sync_request_t l_sync_request = {{0}};
            dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch(l_node_client->client, dap_stream_ch_chain_get_id() );
            l_sync_request.ts_start = (uint64_t) dap_db_log_get_last_timestamp_remote( l_remote_node_info->hdr.address.uint64 );
            //l_sync_request.ts_end = (time_t) time(NULL);
            l_sync_request.node_addr.uint64 = dap_chain_net_get_cur_addr(l_net)?dap_chain_net_get_cur_addr(l_net)->uint64:
                                                                                dap_db_get_cur_node_addr();
            dap_chain_id_t l_chain_id_null = {{0}};
            dap_chain_cell_id_t l_chain_cell_id_null = {{0}};
            log_it(L_INFO,"Requested GLOBAL_DB syncronizatoin, %llu:%llu period", l_sync_request.ts_start,
                   l_sync_request.ts_end ) ;
            if( 0 == dap_stream_ch_chain_pkt_write(l_ch_chain,DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB,
                                                   l_net->pub.id, l_chain_id_null ,l_chain_cell_id_null ,&l_sync_request,
                                                sizeof (l_sync_request))) {
                dap_chain_node_cli_set_reply_text(str_reply, "Error: Cant send sync chains request");
                // clean client struct
                dap_chain_node_client_close(l_node_client);
                DAP_DELETE(l_remote_node_info);
                return -1;
            }
            dap_stream_ch_set_ready_to_write(l_ch_chain,true);
            // wait for finishing of request
            timeout_ms = 120000; // 2 min = 120 sec = 120 000 ms
            // TODO add progress info to console
            res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);

            // Requesting chains
            dap_chain_t *l_chain = NULL;
            DL_FOREACH(l_net->pub.chains, l_chain) {
                // send request
                dap_stream_ch_chain_sync_request_t l_sync_request = {{0}};
                if( 0 == dap_stream_ch_chain_pkt_write(l_ch_chain,DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS,
                                                    l_net->pub.id, l_chain->id ,l_remote_node_info->hdr.cell_id,&l_sync_request,
                                                    sizeof (l_sync_request))) {
                    dap_chain_node_cli_set_reply_text(str_reply, "Error: Cant send sync chains request");
                    // clean client struct
                    dap_chain_node_client_close(l_node_client);
                    DAP_DELETE(l_remote_node_info);
                    return -1;
                }
                log_it(L_NOTICE, "Requested syncronization for chain \"%s\"",l_chain->name);
                dap_stream_ch_set_ready_to_write(l_ch_chain,true);

                // wait for finishing of request
                timeout_ms = 120000; // 2 min = 120 sec = 120 000 ms
                // TODO add progress info to console
                res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
            }
            log_it(L_INFO,"Chains and gdb are synced");
            DAP_DELETE(l_remote_node_info);
            dap_client_disconnect(l_node_client->client);
            dap_chain_node_client_close(l_node_client);
            dap_chain_node_cli_set_reply_text(str_reply, "Node sync completed: Chains and gdb are synced");
            return 0;

        } break;
            // make handshake
        case CMD_HANDSHAKE: {
            // get address from alias if addr not defined
            if(alias_str && !address.uint64) {
                dap_chain_node_addr_t *address_tmp = dap_chain_node_addr_get_by_alias(alias_str);
                if(address_tmp) {
                    memcpy(&address, address_tmp, sizeof(address_tmp));
                    DAP_DELETE(address_tmp);
                }
                else {
                    dap_chain_node_cli_set_reply_text(str_reply, "no address found by alias");
                    return -1;
                }
            }
            if(!address.uint64) {
                dap_chain_node_cli_set_reply_text(str_reply, "addr not found");
                return -1;
            }

            dap_chain_node_info_t *node_info = dap_chain_node_info_read_and_reply(&address, str_reply);
            if(!node_info)
                return -1;
            int timeout_ms = 10000; //10 sec = 10000 ms
            // start handshake
            dap_chain_node_client_t *client = dap_chain_node_client_connect(node_info);
            if(!client) {
                dap_chain_node_cli_set_reply_text(str_reply, "can't connect");
                DAP_DELETE(node_info);
                return -1;
            }
            // wait handshake
            int res = dap_chain_node_client_wait(client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
            if(res != 1) {
                dap_chain_node_cli_set_reply_text(str_reply, "no response from node");
                // clean client struct
                dap_chain_node_client_close(client);
                DAP_DELETE(node_info);
                return -1;
            }
            DAP_DELETE(node_info);

            //Add new established connection in the list
            int ret = dap_chain_node_client_list_add(&address, client);
            switch (ret)
            {
            case -1:
                dap_chain_node_client_close(client);
                dap_chain_node_cli_set_reply_text(str_reply, "connection established, but not saved");
                return -1;
            case -2:
                dap_chain_node_client_close(client);
                dap_chain_node_cli_set_reply_text(str_reply, "connection already present");
                return -1;
            }
            dap_chain_node_cli_set_reply_text(str_reply, "connection established");
        } break;
    }
    return 0;
}

/**
 * Traceroute command
 *
 * return 0 OK, -1 Err
 */
int com_traceroute(int argc, const char** argv, char **str_reply)
{
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
}

/**
 * Tracepath command
 *
 * return 0 OK, -1 Err
 */
int com_tracepath(int argc, const char** argv, char **str_reply)
{
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
}

/**
 * Ping command
 *
 * return 0 OK, -1 Err
 */
int com_ping(int argc, const char** argv, char **str_reply)
{
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
    int res = (addr) ? ping_util(addr, n) : -EADDRNOTAVAIL;
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
}

/**
 * Help command
 */
int com_help(int argc, const char ** argv, char **str_reply)
{
    if(argc > 1) {
        log_it(L_DEBUG, "Help for command %s", argv[1]);
        dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_find(argv[1]);
        if(l_cmd) {
            dap_chain_node_cli_set_reply_text(str_reply, "%s:\n%s", l_cmd->doc, l_cmd->doc_ex);
            return 0;
        } else {
            dap_chain_node_cli_set_reply_text(str_reply, "command \"%s\" not recognized", argv[1]);
            return -1;
        }
    } else {
        // TODO Read list of commands & return it
        log_it(L_DEBUG, "General help requested");
        dap_string_t * l_help_list_str = dap_string_new(NULL);
        dap_chain_node_cmd_item_t *l_cmd = dap_chain_node_cli_cmd_get_first();
        dap_string_printf(l_help_list_str, "");
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
    return -1;
}

/**
 * com_tx_create command
 *
 * Wallet info
 */
int com_tx_wallet(int argc, const char ** argv, char **str_reply)
{
    const char *c_wallets_path = dap_config_get_item_str(g_config, "general", "wallets_path");
    // Get address of wallet
    enum {
        CMD_NONE, CMD_WALLET_NEW, CMD_WALLET_LIST, CMD_WALLET_INFO
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *cmd_str = NULL;
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
                "format of command: wallet [new -w <wallet_name> | list | info -addr <addr> -w <wallet_name>]");
        return -1;
    }

    dap_chain_node_addr_t address;
    memset(&address, 0, sizeof(dap_chain_node_addr_t));
    const char *addr_str = NULL, *wallet_name = NULL;
    // find wallet addr
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-w", &wallet_name);

    dap_string_t *l_string_ret = dap_string_new(NULL);
    switch (cmd_num) {
    // new wallet
    case CMD_WALLET_NEW: {
        if(!wallet_name) {
            dap_chain_node_cli_set_reply_text(str_reply,
                    "wallet name option <-w>  not defined");
            return -1;
        }
        dap_chain_sign_type_t l_sign_type = { SIG_TYPE_TESLA };
        dap_chain_net_id_t l_net_id = { 0x1 };
        // Creates new wallet
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_create(wallet_name, c_wallets_path, l_net_id, l_sign_type);
        dap_chain_addr_t *l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet);
        if(!l_wallet || !l_addr) {
            dap_chain_node_cli_set_reply_text(str_reply, "wallet is not created");
            return -1;
        }
        char *l_addr_str = dap_chain_addr_to_str(l_addr);
        dap_string_append_printf(l_string_ret, "wallet '%s' successfully created\n", l_wallet->name);
        dap_string_append_printf(l_string_ret, "new address %s", l_addr_str);
        DAP_DELETE(l_addr_str);
        dap_chain_wallet_close(l_wallet);
    }
        break;
        // wallet list
    case CMD_WALLET_LIST: {
        DIR * l_dir = opendir(c_wallets_path);
        if( l_dir ) {
            struct dirent * l_dir_entry;
            while((l_dir_entry=readdir(l_dir))!=NULL){
                const char *l_file_name = l_dir_entry->d_name;
                size_t l_file_name_len = (l_file_name) ? strlen(l_file_name) : 0;
                if( (l_file_name_len > 8 )&& ( strcmp(l_file_name + l_file_name_len - 8, ".dwallet") == 0 ) ) {
                    char *l_file_path_tmp = dap_strdup_printf("%s/%s", c_wallets_path, l_file_name);
                    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_file_path_tmp);
                    if(l_wallet) {
                        dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(l_wallet);
                        char *l_addr_str = dap_chain_addr_to_str(l_addr);
                        dap_string_append_printf(l_string_ret, "\nwallet: %s\n", l_wallet->name);
                        dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");
                        DAP_DELETE(l_addr_str);
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

        if(wallet_name) {
            l_wallet = dap_chain_wallet_open(wallet_name, c_wallets_path);
            l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet);
        }
        if(!l_addr && addr_str)
            l_addr = dap_chain_str_to_addr(addr_str);

        if(l_addr) {
            char *l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_addr);
            if(l_wallet)
                dap_string_append_printf(l_string_ret, "\nwallet: %s\n", l_wallet->name);
            dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");

            size_t l_addr_tokens_size = 0;
            char **l_addr_tokens = NULL;
            dap_chain_utxo_addr_get_token_ticker_all(l_addr, &l_addr_tokens, &l_addr_tokens_size);
            if(l_addr_tokens_size > 0)
                dap_string_append_printf(l_string_ret, "balance:\n");
            else
                dap_string_append_printf(l_string_ret, "balance: 0\n");
            for(size_t i = 0; i < l_addr_tokens_size; i++) {
                if(l_addr_tokens[i]) {
                    uint64_t balance = dap_chain_utxo_calc_balance(l_addr, l_addr_tokens[i]);
                    dap_string_append_printf(l_string_ret, "          %llu %s\n", balance, l_addr_tokens[i]);
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

    char *l_str_ret_tmp = dap_string_free(l_string_ret, false);
    char *str_ret = dap_strdup(l_str_ret_tmp);
    dap_chain_node_cli_set_reply_text(str_reply, str_ret);
    DAP_DELETE(l_str_ret_tmp);
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
int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index,int argc, const char ** argv, char ** a_str_reply,
                             dap_chain_t ** a_chain, dap_chain_net_t ** a_net)
{
    const char * l_chain_str = NULL;
    const char * l_net_str = NULL;

    // Net name
    if ( a_net )
        dap_chain_node_cli_find_option_val(argv, *a_arg_index, argc, "-net", &l_net_str);
    else
       return -100;

    // Select network
    if(!l_net_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "%s requires parameter 'net'",argv[0]);
        return -101;
    }

    if ( ( *a_net  = dap_chain_net_by_name(l_net_str) ) == NULL ){ // Can't find such network
        dap_chain_node_cli_set_reply_text(a_str_reply, "%s cand find network \"%s\"",argv[0],l_net_str);
        return -102;
    }

    // Chain name
    if ( a_chain ){
        dap_chain_node_cli_find_option_val(argv, *a_arg_index, argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if ( ( *a_chain  = dap_chain_net_get_chain_by_name(*a_net, l_chain_str ) ) == NULL ){ // Can't find such chain
                dap_chain_node_cli_set_reply_text(a_str_reply, "%s requires parameter 'chain' to be valid chain name in chain net %s",
                                                  argv[0] , l_net_str);
                return -103;
            }
        }
    }
    return  0;

}

/**
 * @brief com_token_decl_sign
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
int com_token_decl_sign(int argc, const char ** argv, char ** a_str_reply)
{
    int arg_index = 1;

    const char * l_datum_hash_str = NULL;
    // Chain name
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "datum", &l_datum_hash_str);

    if ( l_datum_hash_str ){
        const char * l_certs_str = NULL;
        dap_chain_cert_t ** l_certs = NULL;
        size_t l_certs_size = 0;
        dap_chain_t * l_chain;

        dap_chain_net_t * l_net = NULL;

        if ( dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain, &l_net) < 0 )
            return -1;

        // Load certs lists
        size_t l_signs_size = dap_chain_cert_parse_str_list(l_certs_str,&l_certs, &l_certs_size);
        if(!l_certs_size) {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                    "token_create command requres at least one valid certificate to sign the basic transaction of emission");
            return -7;
        }
        size_t l_certs_count = l_certs_size / sizeof(dap_chain_cert_t *);

        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);

        log_it (L_DEBUG, "Requested to sign token declaration %s in gdb://%s with certs %s",
                l_gdb_group_mempool,l_datum_hash_str,                l_certs_str);

        dap_chain_datum_t * l_datum = NULL;
        size_t l_datum_size = 0;
        if( (l_datum = (dap_chain_datum_t*) dap_chain_global_db_gr_get(
                    l_datum_hash_str ,&l_datum_size,l_gdb_group_mempool )) != NULL ) {

            // Check if its token declaration
            if ( l_datum->header.type_id == DAP_CHAIN_DATUM_TOKEN_DECL ){
                dap_chain_datum_token_t * l_datum_token = (dap_chain_datum_token_t *) l_datum->data;
                size_t l_datum_token_size = l_datum->header.data_size;
                size_t l_signs_size = l_datum_token_size - sizeof(l_datum_token->header);

                // Check for signatures, are they all in set and are good enought?
                size_t l_signs_count = 0;

                for ( size_t l_offset = 0; l_offset < l_signs_size; l_signs_count++ ) {
                    dap_chain_sign_t * l_sign = (dap_chain_sign_t *) l_datum_token->signs + l_offset;
                    l_offset += dap_chain_sign_get_size(l_sign);
                    if ( dap_chain_sign_verify(l_sign,&l_datum_token->header,sizeof (l_datum_token->header) ) != 1 ){
                        log_it(L_WARNING,"Wrong signature for datum_token with key %s in mempool!",l_datum_hash_str );
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Datum %s with datum token has wrong signature %u, break process and exit",
                                                          l_datum_hash_str, l_signs_count+1);
                        DAP_DELETE(l_datum);
                        DAP_DELETE(l_datum_token);
                        DAP_DELETE(l_gdb_group_mempool);
                        return -666;
                    }
                }
                log_it( L_DEBUG,"Datum % with token declaration: %u signatures are verified well", l_signs_count);

                // Check if all signs are present
                if ( l_signs_count == l_datum_token->header.signs_total ){
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Datum %s with datum token has all signs on board. Can't add anything in it");
                    DAP_DELETE(l_datum);
                    DAP_DELETE(l_datum_token);
                    DAP_DELETE(l_gdb_group_mempool);
                    return -7;
                } // Check if more signs that could be (corrupted datum)
                else if ( l_signs_count > l_datum_token->header.signs_total ){
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Warning! Datum %s with datum token has more signs on board (%u) than its possible to have (%u)!",
                                                      l_signs_count, l_datum_token->header.signs_total );
                    DAP_DELETE(l_datum);
                    DAP_DELETE(l_datum_token);
                    DAP_DELETE(l_gdb_group_mempool);
                    return -8;
                } // Check if we have enough place to sign the datum token declaration
                else if (  l_datum_token->header.signs_total - l_signs_count < l_certs_count ){
                    l_datum = DAP_REALLOC(l_datum, l_datum_size+ l_signs_size ); // add place for new signatures
                    size_t l_offset =  0;
                    for ( size_t i = 0 ; i < l_certs_count ; i++ ){
                        dap_chain_sign_t * l_sign = dap_chain_sign_create( l_certs[i]->enc_key,
                                                                           &l_datum_token->header,
                                                                           sizeof (l_datum_token->header), 0 );
                        size_t l_sign_size = dap_chain_sign_get_size(l_sign);
                        if ( l_offset + l_sign_size <= l_signs_size ){
                            memcpy( l_datum_token->signs  + l_datum_token_size - sizeof (l_datum_token->header) + l_offset,
                                l_sign,l_sign_size );
                            log_it (L_DEBUG, "Added datum token declaration sign with cert %s", l_certs[i]->name);
                        }

                        DAP_DELETE( l_sign);
                        l_offset += l_sign_size;
                        if (l_offset > l_signs_size ){
                            break;
                        }
                    }
                    l_datum_size += l_signs_size;


                    // Recalc hash, string and place new datum

                    // Calc datum's hash
                    dap_chain_hash_fast_t l_key_hash;
                    dap_hash_fast(l_datum,l_datum_size, &l_key_hash);
                    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);

                    // Add datum to mempool with datum_token hash as a key
                    if(dap_chain_global_db_gr_set(l_key_str, (uint8_t *) l_datum, l_datum_size,l_gdb_group_mempool )) {
                        // Remove old datum from pool
                        if (dap_chain_global_db_gr_del(l_datum_hash_str,l_gdb_group_mempool) ){
                            dap_chain_node_cli_set_reply_text(a_str_reply, "datum %s produced from %s is replacing the %s in datum pool",
                                                              l_key_str, l_datum_hash_str,l_datum_hash_str);

                            DAP_DELETE(l_datum);
                            DAP_DELETE(l_datum_token);
                            DAP_DELETE(l_gdb_group_mempool);
                            return  0;
                        } else {
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Warning! Can't remove old datum %s ( new datum %s added normaly in datum pool)",
                                                               l_datum_hash_str,l_key_str);
                            DAP_DELETE(l_datum);
                            DAP_DELETE(l_datum_token);
                            DAP_DELETE(l_gdb_group_mempool);
                            return 1;
                        }

                    }
                    else{
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Error! datum %s produced from %s can't be placed in mempool",
                                                          l_key_str, l_datum_hash_str);
                        DAP_DELETE(l_datum);
                        DAP_DELETE(l_datum_token);
                        DAP_DELETE(l_gdb_group_mempool);
                        return -2;
                    }

                } else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Not enought place for new signature (%u is left when we need %u signatures)",
                                                       l_datum_token->header.signs_total - l_signs_count, l_certs_count );
                    return -6;
                }
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Wrong datum type. token_decl_sign sign only token declarations datum");
                return -61;
            }
        }else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "token_decl_sign can't find datum with %s hash in the mempool of %s:%s", l_net->pub.name,l_chain->name);
            return -5;
        }
    }else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "token_decl_sign need datum <datum hash> argument");
        return -2;
    }
}


/**
 * @brief com_token_decl_list
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
int com_mempool_list(int argc, const char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain, &l_net) != 0){
        return -1;
    }

    if ( l_chain && l_net ){
        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
        dap_string_t * l_str_tmp = dap_string_new(NULL);

        size_t l_objs_size = 0;

        dap_global_db_obj_t ** l_objs = dap_chain_global_db_gr_load(l_gdb_group_mempool,&l_objs_size);
        dap_string_append_printf(l_str_tmp,"%s.%s: Found %u records :\n",l_net->pub.name,l_chain->name,l_objs_size);
        for ( size_t i = 0; i< l_objs_size; i++){
            dap_chain_datum_t * l_datum =(dap_chain_datum_t* ) l_objs[i]->value;
            char buf[50];
            time_t l_ts_create = (time_t) l_datum->header.ts_create;
            dap_string_append_printf(l_str_tmp,"%s: type_id=%s  data_size=%u ts_create=%s",
                                     l_objs[i]->key, c_datum_type_str[l_datum->header.type_id],
                                        l_datum->header.data_size,ctime_r( &l_ts_create,buf ) );
        }

        // Clean up
        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
        dap_chain_global_db_objs_delete(l_objs);
        dap_string_free(l_str_tmp,false);

        return  0;
    }else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Need both -net <network name> and -chain <chain name> params\n");
        return -2;
    }
}

/**
 * @brief com_mempool_delete
 * @param argc
 * @param argv
 * @param a_str_reply
 * @return
 */
int com_mempool_delete(int argc, const char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain, &l_net) != 0){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Need both -net <network name> and -chain <chain name> params\n");
        return -1;
    }

    if ( l_chain && l_net ){
        const char * l_datum_hash_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
        if ( l_datum_hash_str ){
            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
            if ( dap_chain_global_db_gr_del(l_datum_hash_str,l_gdb_group_mempool) ) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Datum %s deleted",l_datum_hash_str);
                return  0;
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Can't find datum %s",l_datum_hash_str);
                return  -4;
            }
        }else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Error! %s requires -datum <datum hash> option",argv[0]);
            return -3;
        }
    }else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Error! Need both -net <network name> and -chain <chain name> params\n");
        return -2;
    }
}

/**
 * @brief com_mempool_proc
 * @param argc
 * @param argv
 * @param a_str_reply
 * @return
 */
int com_mempool_proc(int argc, const char ** argv, char ** a_str_reply)
{
    int arg_index = 1;
    dap_chain_t * l_chain;
    dap_chain_net_t * l_net = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain, &l_net) < 0)
        return -1;

    char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    size_t l_objs_size = 0;
    dap_global_db_obj_t ** l_objs = dap_chain_global_db_gr_load(l_gdb_group_mempool,&l_objs_size);
    dap_string_t * l_str_tmp = dap_string_new(NULL);
    if ( l_objs_size ) {
        dap_string_append_printf(l_str_tmp,"%s.%s: Found %u records :\n",l_net->pub.name,l_chain->name);


        size_t l_datums_size = l_objs_size;
        dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,sizeof(dap_chain_datum_t*)*l_datums_size);
        for ( size_t i = 0; i< l_objs_size; i++){
            dap_chain_datum_t * l_datum = (dap_chain_datum_t* ) l_objs[i]->value;
            l_datums[i] = l_datum;
            char buf[50];
            time_t l_ts_create = (time_t) l_datum->header.ts_create;
            dap_string_append_printf(l_str_tmp,"0x%s: type_id=%s ts_create=%s data_size=%u\n",
                                     l_objs[i]->key, c_datum_type_str[l_datum->header.type_id],
                                        ctime_r( &l_ts_create,buf ),l_datum->header.data_size );
        }
        size_t l_objs_processed = l_chain->callback_datums_pool_proc(l_chain,l_datums,l_datums_size);
        // Delete processed objects
        for ( size_t i = 0; i< l_objs_processed; i++){
            dap_chain_global_db_gr_del(l_objs[i]->key,l_gdb_group_mempool);
            dap_string_append_printf(l_str_tmp,"New event created, removed datum 0x%s from mempool \n",l_objs[i]->key);
        }
        dap_chain_global_db_objs_delete(l_objs);

        dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
        dap_string_free(l_str_tmp,false);
    }else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "%s.^s: No records in mempool",l_net->pub.name,l_chain->name);
    }
    return 0;
}



/**
 * @brief com_token_decl
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
int com_token_decl(int argc, const char ** argv, char ** str_reply)
{
    int arg_index = 1;
    const char *str_tmp = NULL;
    char *str_reply_tmp = NULL;
    const char * l_ticker = NULL;

    const char * l_total_supply_str = NULL;
    uint64_t l_total_supply = 0;

    const char * l_signs_emission_str = NULL;
    uint16_t l_signs_emission = 0;

    const char * l_signs_total_str = NULL;
    uint16_t l_signs_total = 0;


    const char * l_certs_str = NULL;

    dap_chain_cert_t ** l_certs = NULL;
    size_t l_certs_size = 0;

    dap_chain_t * l_chain;
    dap_chain_net_t * l_net = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,str_reply,&l_chain, &l_net) < 0)
        return -1;



    // Total supply value
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "total_supply", &l_total_supply_str);

    // Token ticker
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "token", &l_ticker);


    // Certificates thats will be used to sign currend datum token
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "certs", &l_certs_str);

    // Signs number thats own emissioncan't find
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "signs_total", &l_signs_total_str);

    // Signs minimum number thats need to authorize the emission
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "signs_emission", &l_signs_emission_str);

    if(!l_total_supply_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'total_supply'");
        return -11;
    }else {
        char * l_tmp = NULL;
        if ( ( l_total_supply = strtoull(l_total_supply_str,&l_tmp,10) ) == 0 ){
            dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'total_supply' to be unsigned integer value that fits in 8 bytes");
            return -2;
        }
    }

    // Signs emission
    if(!l_signs_emission_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'signs_emission'");
        return -3;
    }else {
        char * l_tmp = NULL;
        if ( ( l_signs_emission  =(uint16_t)  strtol(l_signs_emission_str,&l_tmp,10) ) == 0 ){
            dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'signs_emission' to be unsigned integer value that fits in 2 bytes");
            return -4;
        }
    }

    // Signs total
    if(!l_signs_total_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'signs_total'");
        return -31;
    }else {
        char * l_tmp = NULL;
        if ( ( l_signs_total  =(uint16_t)  strtol(l_signs_total_str,&l_tmp,10) ) == 0 ){
            dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'signs_total' to be unsigned integer value that fits in 2 bytes");
            return -41;
        }
    }


    // Check for ticker
    if(!l_ticker) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_emit requires parameter 'token'");
        return -5;
    }


    // Check certs list
    if(!l_certs_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_emit requires parameter 'certs'");
        return -6;
    }

    // Load certs lists
    size_t l_signs_size = dap_chain_cert_parse_str_list(l_certs_str,&l_certs, &l_certs_size);
    if(!l_certs_size) {
        dap_chain_node_cli_set_reply_text(str_reply,
                "token_create command requres at least one valid certificate to sign the basic transaction of emission");
        return -7;
    }

    // If we have more certs than we need signs - use only first part of the list
    if (l_certs_size > l_signs_total )
        l_certs_size = l_signs_total;

    // Create new datum token
    dap_chain_datum_token_t * l_datum_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t,sizeof(l_datum_token->header) +
                                                             l_signs_size);
    l_datum_token->header.version = 1; // Current version
    snprintf(l_datum_token->header.ticker,sizeof(l_datum_token->header.ticker),"%s",l_ticker);
    l_datum_token->header.total_supply = l_total_supply;
    l_datum_token->header.signs_total = l_signs_total;
    l_datum_token->header.signs_valid = l_signs_emission;

    size_t l_signs_offset = 0;
    // Sign header with all certificates in the list and add signs to the end of ticker declaration
    // Important:
    for ( size_t i = 0 ; i < l_certs_size; i++ ){
        dap_chain_sign_t * l_sign = dap_chain_cert_sign( l_certs[i],
                                                         l_datum_token,
                                                         sizeof(l_datum_token->header),
                                                         0);
        size_t l_sign_size = dap_chain_sign_get_size(l_sign);
        memcpy(l_datum_token->signs+l_signs_offset,l_sign,l_sign_size);
        DAP_DELETE(l_sign);
    }
    dap_chain_datum_t * l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_DECL,l_datum_token,
                                                         sizeof (l_datum_token->header)+ l_signs_size);
    size_t l_datum_size = dap_chain_datum_size(l_datum);

    // Calc datum's hash
    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_datum,l_datum_size, &l_key_hash);
    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);

    // Add datum to mempool with datum_token hash as a key
    char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    if(dap_chain_global_db_gr_set(l_key_str, (uint8_t *) l_datum, l_datum_size,l_gdb_group_mempool )) {
        dap_chain_node_cli_set_reply_text(str_reply, "%s\ndatum %s with token %s is placed in datum pool ", str_reply_tmp, l_key_str,l_ticker);
        DAP_DELETE(l_datum);
        DAP_DELETE(l_datum_token);
        DAP_DELETE(l_gdb_group_mempool);
        return  0;
    }
    else{
        dap_chain_node_cli_set_reply_text(str_reply, "%s\ndatum tx %s is not placed in datum pool ", str_reply_tmp, l_key_str);
        DAP_DELETE(l_datum);
        DAP_DELETE(l_datum_token);
        DAP_DELETE(l_gdb_group_mempool);
        return -2;
    }

}

/**
 * @brief com_token_emit
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
int com_token_emit(int argc, const char ** argv, char ** str_reply)
{
    int arg_index = 1;
    const char *str_tmp = NULL;
    char *str_reply_tmp = NULL;
    uint64_t l_emission_value = 0;

    const char * l_ticker = NULL;

    const char * l_addr_str = NULL;

    const char * l_certs_str = NULL;

    dap_chain_cert_t ** l_certs = NULL;
    size_t l_certs_size = 0;

    const char * l_chain_emission_str = NULL;
    dap_chain_t * l_chain_emission = NULL;

    const char * l_chain_base_tx_str = NULL;
    dap_chain_t * l_chain_base_tx = NULL;

    const char * l_net_str = NULL;
    dap_chain_net_t * l_net = NULL;


    // Wallet address that recieves the emission
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "certs", &l_certs_str);

    // Wallet address that recieves the emission
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "addr", &l_addr_str);

    // Token ticker
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "token", &l_ticker);

    // Token emission
    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "emission_value", &str_tmp)) {
        l_emission_value = strtoull(str_tmp, NULL, 10);
    }

    if(!l_emission_value) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_emit requires parameter 'emission_value'");
        return -1;
    }

    if(!l_addr_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_emit requires parameter 'addr'");
        return -2;
    }

    if(!l_ticker) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_emit requires parameter 'token'");
        return -3;
    }

    if(!l_certs_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_emit requires parameter 'certs'");
        return -4;
    }

    // Load certs
    dap_chain_cert_parse_str_list(l_certs_str,&l_certs,&l_certs_size);

    if(!l_certs_size) {
        dap_chain_node_cli_set_reply_text(str_reply,
                "token_emit command requres at least one valid certificate to sign the basic transaction of emission");
        return -5;
    }


    dap_chain_addr_t * l_addr = dap_chain_str_to_addr(l_addr_str);

    if(!l_addr) {
        dap_chain_node_cli_set_reply_text(str_reply, "address \"%s\" is invalid", l_addr_str);
        return -4;
    }

    // Select chain network
    if(!l_net_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'net'");
        return -42;
    }else {
        if ( ( l_net  = dap_chain_net_by_name(l_net_str) ) == NULL ){ // Can't find such network
            dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'net' to be valid chain network name");
            return -43;
        }
    }


    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "chain_emission", &l_chain_emission_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "chain_base_tx", &l_chain_base_tx_str);

    // Select chain emission
    if(!l_chain_emission_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'chain_emission'");
        return -44;
    }else {
        if ( ( l_chain_emission  = dap_chain_net_get_chain_by_name(l_net, l_chain_emission_str ) ) == NULL ){ // Can't find such chain
            dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'chain_emission' to be valid chain name in chain net %s",l_net_str);
            return -45;
        }
    }

    // Select chain emission
    if(!l_chain_base_tx_str) {
        dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'chain_base_tx'");
        return -46;
    }else {
        if ( ( l_chain_base_tx  = dap_chain_net_get_chain_by_name(l_net, l_chain_base_tx_str ) ) == NULL ){ // Can't find such chain
            dap_chain_node_cli_set_reply_text(str_reply, "token_create requires parameter 'chain_emission' to be valid chain name in chain net %s",l_net_str);
            return -47;
        }
    }

    // Get mempool group for this chain
    char * l_gdb_group_mempool_emission = dap_chain_net_get_gdb_group_mempool(l_chain_emission);
    char * l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool(l_chain_base_tx);


    // Create emission datum
    dap_chain_datum_token_emission_t * l_token_emission;
    dap_chain_hash_fast_t l_token_emission_hash;
    l_token_emission = DAP_NEW_Z(dap_chain_datum_token_emission_t);
    strncpy(l_token_emission->ticker, l_ticker, sizeof(l_token_emission->ticker));
    l_token_emission->value = l_emission_value;
    dap_hash_fast(l_token_emission, sizeof(dap_chain_datum_token_emission_t), &l_token_emission_hash);
    dap_chain_datum_t * l_datum_emission = dap_chain_datum_create(DAP_CHAIN_DATUM_TOKEN_EMISSION,
            l_token_emission,
            sizeof(dap_chain_datum_token_emission_t));
    size_t l_datum_emission_size = sizeof(l_datum_emission->header) + l_datum_emission->header.data_size;

    DAP_DELETE(l_token_emission);

    dap_chain_hash_fast_t l_key_hash;
    dap_hash_fast(l_datum_emission, l_datum_emission_size, &l_key_hash);
    char * l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);

    // Add to mempool emission token
    if(dap_chain_global_db_gr_set(l_key_str, (uint8_t *) l_datum_emission, l_datum_emission_size
            , l_gdb_group_mempool_emission)) {
        str_reply_tmp = dap_strdup_printf("datum emission %s is placed in datum pool ", l_key_str);
    }
    else {
        dap_chain_node_cli_set_reply_text(str_reply, "datum emission %s is not placed in datum pool ", l_key_str);
        return -1;
    }
    DAP_DELETE(l_key_str);

    // create first transaction (with tx_token)
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    dap_chain_hash_fast_t l_tx_prev_hash = { 0 };
    dap_chain_hash_fast_t l_datum_token_hash = { 0 };
    // create items
    dap_chain_tx_token_t *l_tx_token = dap_chain_datum_tx_item_token_create(&l_token_emission_hash, l_ticker);
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(l_addr, l_emission_value);

    // pack items to transaction
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_token);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);

    // Sign all that we have with certs
    for(size_t i = 0; i < l_certs_size; i++) {
        if(dap_chain_datum_tx_add_sign_item(&l_tx, l_certs[i]->enc_key) < 0) {
            dap_chain_node_cli_set_reply_text(str_reply, "No private key for certificate=%s",
                    l_certs[i]->name);
            return -3;
        }
    }

    DAP_DELETE(l_certs);
    DAP_DELETE(l_tx_token);
    DAP_DELETE(l_in);
    DAP_DELETE(l_out);

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);

    // Pack transaction into the datum
    dap_chain_datum_t * l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);

    // use l_tx hash for compatible with utho hash
    //dap_hash_fast(l_tx, l_tx_size, &l_key_hash); //dap_hash_fast(l_datum_tx, l_datum_tx_size, &l_key_hash);
    // calc datum hash
    dap_hash_fast(l_datum_tx, l_datum_tx_size, &l_key_hash);
    l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    DAP_DELETE(l_tx);


    // Add to mempool tx token
    if(dap_chain_global_db_gr_set(l_key_str, (uint8_t *) l_datum_tx, l_datum_tx_size
            , l_gdb_group_mempool_base_tx)) {
        dap_chain_node_cli_set_reply_text(str_reply, "%s\ndatum tx %s is placed in datum pool ", str_reply_tmp, l_key_str);
        dap_chain_utxo_tx_add((dap_chain_datum_tx_t*) l_datum_tx->data);
    }
    else {
        dap_chain_node_cli_set_reply_text(str_reply, "%s\ndatum tx %s is not placed in datum pool ", str_reply_tmp,
                l_key_str);
        return -2;
    }
    DAP_DELETE(str_reply_tmp);
    DAP_DELETE(l_key_str);

    return 0;
}

/**
 * com_tx_cond_create command
 *
 * Create transaction
 */
int com_tx_cond_create(int argc, const char ** argv, char **str_reply)
{
    // test
    const char * l_token_ticker = NULL;
    const char *c_wallets_path = dap_config_get_item_str(g_config, "general", "wallets_path");
    const char *c_wallet_name_from = "w_tesla"; // where to take coins for service
    const char *c_wallet_name_cond = "w_picnic"; // who will be use service, usually the same address (addr_from)
    uint64_t l_value = 50;
    //debug
    {
        dap_chain_wallet_t * l_wallet_tesla = dap_chain_wallet_open("w_picnic", c_wallets_path);
        const dap_chain_addr_t *l_addr_tesla = dap_chain_wallet_get_addr(l_wallet_tesla);
        char *addr = dap_chain_addr_to_str(l_addr_tesla);
        addr = 0;
    }

    dap_chain_wallet_t *l_wallet_from = dap_chain_wallet_open(c_wallet_name_from, c_wallets_path);
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(l_wallet_from, 0);
    dap_chain_wallet_t *l_wallet_cond = dap_chain_wallet_open(c_wallet_name_cond, c_wallets_path);
    dap_enc_key_t *l_key_cond = dap_chain_wallet_get_key(l_wallet_cond, 0);
    // where to take coins for service
    const dap_chain_addr_t *addr_from = dap_chain_wallet_get_addr(l_wallet_from);
    // who will be use service, usually the same address (addr_from)
    const dap_chain_addr_t *addr_cond = dap_chain_wallet_get_addr(l_wallet_cond);

    dap_chain_net_srv_abstract_t l_cond;
//    dap_chain_net_srv_abstract_set(&l_cond, SERV_CLASS_PERMANENT, SERV_ID_VPN, l_value, SERV_UNIT_MB,
//            "test vpn service");
    int res = dap_chain_mempool_tx_create_cond(l_key, l_key_cond, addr_from,
            addr_cond,
            NULL, l_token_ticker, l_value, 0, (const void*) &l_cond, sizeof(dap_chain_net_srv_abstract_t));

    dap_chain_wallet_close(l_wallet_from);
    dap_chain_wallet_close(l_wallet_cond);
    dap_chain_node_cli_set_reply_text(str_reply, "cond create=%s\n",
            (res == 0) ? "Ok" : (res == -2) ? "False, not enough funds for service fee" : "False");
    return res;
}

/**
 * com_tx_create command
 *
 * Create transaction
 */
int com_tx_create(int argc, const char ** argv, char **str_reply)
{
    int arg_index = 1;
    int cmd_num = 1;
    const char *value_str = NULL;
    const char *addr_base58_to = NULL;
    const char *addr_base58_fee = NULL;
    const char *str_tmp = NULL;
    const char * l_from_wallet_name = NULL;
    const char * l_token_ticker = NULL;
    uint64_t value = 0;
    uint64_t value_fee = 0;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "from_wallet_name", &l_from_wallet_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "to_addr", &addr_base58_to);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "token", &l_token_ticker);

    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "fee", &addr_base58_fee)) {
        if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "value_fee", &str_tmp)) {
            value_fee = strtoull(str_tmp, NULL, 10);
        }
    }
    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "value", &str_tmp)) {
        value = strtoull(str_tmp, NULL, 10);
    }
    if(!l_from_wallet_name) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter 'from_wallet_name'");
        return -1;
    }
    if(!addr_base58_to) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter 'to_addr'");
        return -1;
    }
    if(!value) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter 'value'");
        return -1;
    }
    if(addr_base58_fee && !value_fee) {
        dap_chain_node_cli_set_reply_text(str_reply, "tx_create requires parameter 'value_fee' if 'fee' is specified");
        return -1;
    }

    const char *c_wallets_path = dap_config_get_item_str(g_config, "general", "wallets_path");
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(l_from_wallet_name, c_wallets_path);

    if(!l_wallet) {
        dap_chain_node_cli_set_reply_text(str_reply, "wallet %s does not exist", l_from_wallet_name);
        return -1;
    }
    const dap_chain_addr_t *addr_from = (const dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet);
    dap_chain_addr_t *addr_to = dap_chain_str_to_addr(addr_base58_to);
    dap_chain_addr_t *addr_fee = dap_chain_str_to_addr(addr_base58_fee);

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

    int res = dap_chain_mempool_tx_create(dap_chain_wallet_get_key(l_wallet, 0), addr_from, addr_to, addr_fee,
            l_token_ticker, value, value_fee);
    dap_string_append_printf(string_ret, "transfer=%s\n",
            (res == 0) ? "Ok" : (res == -2) ? "False, not enough funds for transfer" : "False");

    char *str_ret_tmp = dap_string_free(string_ret, false);
    char *str_ret = strdup(str_ret_tmp);
    dap_chain_node_cli_set_reply_text(str_reply, str_ret);

    DAP_DELETE(str_ret_tmp);
    DAP_DELETE(addr_to);
    DAP_DELETE(addr_fee);
    dap_chain_wallet_close(l_wallet);
    return res;
}

/**
 * tx_verify command
 *
 * Verifing transaction
 */
int com_tx_verify(int argc, const char ** argv, char **str_reply)
{
    if(argc > 1) {
        if(str_reply)
            dap_chain_node_cli_set_reply_text(str_reply, "command \"%s\" not recognized", argv[1]);
    }
    if(str_reply)
        dap_chain_node_cli_set_reply_text(str_reply, "command not defined, enter \"help <cmd name>\"");
    return -1;
}

/**
 * print_log command
 *
 * Print log info
 * print_log [ts_after <timestamp >] [limit <line numbers>]
 */
int com_print_log(int argc, const char ** argv, char **str_reply)
{
    int arg_index = 1;
    const char * l_str_ts_after = NULL;
    const char * l_str_limit = NULL;
    int64_t l_ts_after = 0;
    int32_t l_limit = 0;
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
    char *l_str_ret = dap_log_get_item(l_ts_after, l_limit);
    if(!l_str_ret) {
        dap_chain_node_cli_set_reply_text(str_reply, "no logs");
        return -1;
    }
    dap_chain_node_cli_set_reply_text(str_reply, l_str_ret);
    DAP_DELETE(l_str_ret);
    return 0;
}


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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <glib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "iputils/iputils.h"
#include "dap_string.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_string.h"
#include "dap_chain_wallet.h"
#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_remote.h"
#include "dap_chain_node_cli_cmd.h"

#include "dap_chain_datum.h"
#include "dap_chain_datum_tx_ctrl.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_cache.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream_ch_chain_net.h"

#define LOG_TAG "chain_node_cli_cmd"

/**
 * find option value
 *
 * return index of string in argv, or 0 if not found
 */
static int find_option_val(const char** argv, int arg_start, int arg_end, const char *opt_name, const char **opt_value)
{
    int arg_index = arg_start;
    int arg_character, on_or_off, next_arg, i;
    char *arg_string;

    while(arg_index < arg_end)
    {
        arg_string = (char *) argv[arg_index];
        // find opt_name
        if(arg_string && opt_name && !strcmp(arg_string, opt_name)) {
            // find opt_value
            if(opt_value) {
                arg_string = (char *) argv[++arg_index];
                if(arg_string) {
                    *opt_value = arg_string;
                    return arg_index;
                }
            }
            else
                // need only opt_name
                return arg_index;
        }
        arg_index++;
    }
    return 0;
}
/**
 * Convert string to digit
 */
static void digit_from_string(const char *num_str, uint8_t *raw, size_t raw_len)
{
    if(!num_str)
        return;
    uint64_t val;
    if(!strncasecmp(num_str, "0x", 2)) {
        val = strtoull(num_str + 2, NULL, 16);
    }
    else {
        val = strtoull(num_str, NULL, 10);
    }
    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
    val = le64toh(val);
    memset(raw, 0, raw_len);
    memcpy(raw, &val, min(raw_len, sizeof(uint64_t)));
}

/**
 * Add alias in base
 */
static bool add_alias(const char *alias, dap_chain_node_addr_t *addr)
{
    const char *a_key = alias;
//    char a_value[2 * sizeof(dap_chain_node_addr_t) + 1];
//    if(bin2hex(a_value, (const unsigned char *) addr, sizeof(dap_chain_node_addr_t)) == -1)
//        return false;
//    a_value[2 * sizeof(dap_chain_node_addr_t)] = '\0';
    bool res = dap_chain_global_db_gr_set(a_key, (const uint8_t*) addr, sizeof(dap_chain_node_addr_t), GROUP_ALIAS);
    return res;
}

/**
 * Delete alias from base
 */
static bool del_alias(const char *alias)
{
    const char *a_key = alias;
    bool res = dap_chain_global_db_gr_del(a_key, GROUP_ALIAS);
    return res;
}

/**
 * Find in base addr by alias
 *
 * return addr, NULL if not found
 */
dap_chain_node_addr_t* get_name_by_alias(const char *a_alias)
{
    dap_chain_node_addr_t *l_addr = NULL;
    if(!a_alias)
        return NULL;
    const char *a_key = a_alias;
    size_t l_addr_out = 0;
    l_addr = (dap_chain_node_addr_t*) dap_chain_global_db_gr_get(a_key, &l_addr_out, GROUP_ALIAS);
    if(l_addr_out != sizeof(dap_chain_node_addr_t)) {
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
    dap_global_db_obj_t **objs = dap_chain_global_db_gr_load(GROUP_ALIAS, &data_size);
    if(!objs || !data_size)
        return NULL;
    for(int i = 0; i < data_size; i++) {
        dap_chain_node_addr_t addr_i;
        dap_global_db_obj_t *obj = objs[i];
        if(!obj)
            break;
        dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t*) obj->value;
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
        address = get_name_by_alias(alias_str);
    }
    if(addr->uint64) {
        address = DAP_NEW(dap_chain_node_addr_t);
        address->uint64 = addr->uint64;
    }
    return address;
}

static char* com_global_db_get_key_for_addr(dap_chain_node_addr_t *address)
{
    char *a_key = dap_chain_global_db_hash((const uint8_t*) address, sizeof(dap_chain_node_addr_t));
    return a_key;
}

/**
 * Write text to reply string
 */
static void set_reply_text(char **str_reply, const char *str, ...)
{
    if(str_reply) {
        if(*str_reply) {
            assert(!*str_reply);
            DAP_DELETE(*str_reply);
            *str_reply = NULL;
        }
        va_list args;
        va_start(args, str);
        *str_reply = dap_strdup_vprintf(str, args); //*str_reply = dap_strdup(str);
        va_end(args);
    }
}

/**
 * Read node from base
 */
static dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_node_addr_t *address, char **str_reply)
{
    char *l_key = com_global_db_get_key_for_addr(address);
    if(!l_key)
    {
        set_reply_text(str_reply, "can't calculate hash of addr");
        return NULL;
    }
    size_t node_info_size = 0;
    dap_chain_node_info_t *node_info;
    // read node
    node_info = (dap_chain_node_info_t *) dap_chain_global_db_gr_get(l_key, &node_info_size, GROUP_NODE);

    if(!node_info) {
        set_reply_text(str_reply, "node not found in base");
        DAP_DELETE(l_key);
        return NULL;
    }
    size_t node_info_size_must_be = dap_chain_node_info_get_size(node_info);
    if(node_info_size_must_be != node_info_size) {
        set_reply_text(str_reply, "node has bad size in base=%u (must be %u)", node_info_size, node_info_size_must_be);
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
static bool dap_chain_node_info_save(dap_chain_node_info_t *node_info, char **str_reply)
{
    if(!node_info || !node_info->hdr.address.uint64) {
        set_reply_text(str_reply, "node addr not found");
        return false;
    }
    char *a_key = com_global_db_get_key_for_addr(&node_info->hdr.address);
    if(!a_key)
    {
        set_reply_text(str_reply, "can't calculate hash for addr");
        return NULL;
    }
    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t node_info_size = dap_chain_node_info_get_size(node_info);
    bool res = dap_chain_global_db_gr_set(a_key, (const uint8_t *) node_info, node_info_size, GROUP_NODE);
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
static int com_global_db_add(dap_chain_node_info_t *node_info, const char *alias_str,
        const char *shard_str, const char *ipv4_str, const char *ipv6_str, char **str_reply)
{

    if(!node_info->hdr.address.uint64) {
        set_reply_text(str_reply, "not found -addr parameter");
        return -1;
    }
    if(!shard_str) {
        set_reply_text(str_reply, "not found -shard parameter");
        return -1;
    }
    if(!ipv4_str && !ipv6_str) {
        set_reply_text(str_reply, "not found -ipv4 or -ipv6 parameter");
        return -1;
    }
    else {
        if(ipv4_str)
            inet_pton(AF_INET, ipv4_str, &(node_info->hdr.ext_addr_v4));
        if(ipv6_str)
            inet_pton(AF_INET6, ipv6_str, &(node_info->hdr.ext_addr_v6));
    }
    // check match addr to shard or no
    /*dap_chain_node_addr_t *addr = dap_chain_node_gen_addr(&node_info->hdr.shard_id);
     if(!dap_chain_node_check_addr(&node_info->hdr.address, &node_info->hdr.shard_id)) {
     set_reply_text(str_reply, "shard does not match addr");
     return -1;
     }*/
    if(alias_str) {
        // add alias
        if(!add_alias(alias_str, &node_info->hdr.address)) {
            log_it(L_WARNING, "can't save alias %s", alias_str);
            set_reply_text(str_reply, "alias '%s' can't be mapped to addr=0x%lld",
                    alias_str, node_info->hdr.address.uint64);
            return -1;
        }
    }

    // write to base
    bool res = dap_chain_node_info_save(node_info, str_reply);
    if(res)
        set_reply_text(str_reply, "node added");
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
        set_reply_text(str_reply, "addr not found");
        return -1;
    }
    // check, current node have this addr or no
    uint64_t l_cur_addr = dap_db_get_cur_node_addr();
    if(l_cur_addr && l_cur_addr == node_info->hdr.address.uint64) {
        set_reply_text(str_reply, "current node cannot be deleted");
        return -1;
    }

    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, &node_info->hdr.address, alias_str);
    if(!address) {
        set_reply_text(str_reply, "alias not found");
        return -1;
    }
    char *a_key = com_global_db_get_key_for_addr(address);
    if(a_key)
    {
        // delete node
        bool res = dap_chain_global_db_gr_del(a_key, GROUP_NODE);
        if(res) {
            // delete all aliases for node address
            {
                dap_list_t *list_aliases = get_aliases_by_name(address);
                dap_list_t *list = list_aliases;
                while(list)
                {
                    const char *alias = (const char *) list->data;
                    del_alias(alias);
                    list = dap_list_next(list);
                }
                dap_list_free_full(list_aliases, (DapDestroyNotify) free);
            }
            // set text response
            set_reply_text(str_reply, "node deleted");
        }
        else
            set_reply_text(str_reply, "node not deleted");
        DAP_DELETE(a_key);
        DAP_DELETE(address);
        if(res)
            return 0;
        return -1;
    }
    set_reply_text(str_reply, "addr to delete can't be defined");
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
        set_reply_text(str_reply, "addr not found");
        return -1;
    }
    if(!link->uint64) {
        set_reply_text(str_reply, "link not found");
        return -1;
    }
    // TODO check the presence of link in the node base
    if(0) {
        set_reply_text(str_reply, "node 0x%llx not found in base", link->uint64);
        return -1;
    }

    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, &node_info->hdr.address, alias_str);
    if(!address) {
        set_reply_text(str_reply, "alias not found");
        return -1;
    }
    dap_chain_node_info_t *node_info_read = dap_chain_node_info_read(address, str_reply);
    if(!node_info_read)
        return -1;

    int cmd_int = 0;
    if(!strcmp(cmd, "add"))
        cmd_int = 1;
    else if(!strcmp(cmd, "del"))
        cmd_int = 2;

    // find link in node_info_read
    int index_link = -1;
    for(int i = 0; i < node_info_read->hdr.links_number; i++) {
        if(node_info_read->links[i].uint64 == link->uint64) {
            // link already present
            index_link = i;
            break;
        }
    }
    bool res_successful = false; // is successful whether add/del
    // add link
    if(cmd_int == 1) {
        if(index_link == -1) {
            memcpy(&(node_info_read->links[node_info_read->hdr.links_number]), link, sizeof(dap_chain_node_addr_t));
            node_info_read->hdr.links_number++;
            res_successful = true;
        }
    }
    // delete link
    else if(cmd_int == 2) {
        // move link list to one item prev
        if(index_link >= 0) {
            for(int j = index_link; j < node_info_read->hdr.links_number - 1; j++) {
                memcpy(&(node_info_read->links[j]), &(node_info_read->links[j + 1]), sizeof(dap_chain_node_addr_t));
            }
            node_info_read->hdr.links_number--;
            res_successful = true;
        }
    }
    // save edited node_info
    if(res_successful) {
        bool res = dap_chain_node_info_save(node_info_read, str_reply);
        if(res) {
            res_successful = true;
            if(cmd_int == 1)
                set_reply_text(str_reply, "link added");
            if(cmd_int == 2)
                set_reply_text(str_reply, "link deleted");
        }
        else {
            res_successful = false;
        }
    }
    else {
        if(cmd_int == 1) {
            if(index_link >= 0)
                set_reply_text(str_reply, "link not added because it is already present");
            else
                set_reply_text(str_reply, "link not added");
        }
        if(cmd_int == 2) {
            if(index_link == -1)
                set_reply_text(str_reply, "link not deleted because not found");
            else
                set_reply_text(str_reply, "link not deleted");
        }
    }

    DAP_DELETE(address);
    DAP_DELETE(node_info_read);
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
        l_objs = dap_chain_global_db_gr_load(GROUP_NODE, &l_nodes_count);
        /*for(size_t i = 0; i < l_nodes_count; i++) {
         dap_global_db_obj_t *l_obj = l_objs[i];
         dap_chain_node_info_t *node_info = (dap_chain_node_info_t *) l_obj->value;
         node_info->

         }*/
        if(!l_nodes_count || !l_objs) {
            set_reply_text(str_reply, "nodes not found");
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
            set_reply_text(str_reply, "alias not found");
            break;
        }
        // read node
        dap_chain_node_info_t *node_info_read = dap_chain_node_info_read(address, str_reply);
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
            dap_list_free_full(list_aliases, (DapDestroyNotify) free);
        }
        else
            dap_string_append(aliases_string, "\nno aliases");

        // get links in form of string
        dap_string_t *links_string = dap_string_new(NULL);
        for(int i = 0; i < node_info_read->hdr.links_number; i++) {
            dap_chain_node_addr_t link_addr = node_info_read->links[i];
            dap_string_append_printf(links_string, "\nlink%02d address : 0x%llx", i, link_addr.uint64);
        }

        if(i)
            dap_string_append_printf(l_string_reply, "\n");
        // set short reply with node param
        if(l_objs)
            dap_string_append_printf(l_string_reply,
                    "node address 0x%llx\tshard 0x%llx\tipv4 %s\tnumber of links %d",
                    node_info_read->hdr.address, node_info_read->hdr.shard_id,
                    str_ip4, node_info_read->hdr.links_number);
        else
            // set full reply with node param
            dap_string_append_printf(l_string_reply,
                    "node address 0x%llx\nshard 0x%llx%s\nipv4 %s\nipv6 %s\nlinks %d%s",
                    node_info_read->hdr.address, node_info_read->hdr.shard_id, aliases_string->str,
                    str_ip4, str_ip6,
                    node_info_read->hdr.links_number, links_string->str);
        dap_string_free(aliases_string, true);
        dap_string_free(links_string, true);

        DAP_DELETE(address);
        DAP_DELETE(node_info_read);
    }
    if(i == l_nodes_count) {
        // set full reply with node param
        set_reply_text(str_reply, l_string_reply->str);
    }
    dap_string_free(l_string_reply, true);
    if(i < l_nodes_count)
        return -1;
    else
        return 0;
}

/**
 * Handler of command 'global_db node get'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_get(char **a_str_reply)
{
    // get cur node addr
    uint64_t l_addr = dap_db_get_cur_node_addr();
    if(l_addr) {
        set_reply_text(a_str_reply, "address for current node is 0x%llu", l_addr);
        return 0;
    }
    set_reply_text(a_str_reply, "address for node has not been set.");
    return -1;
}

/**
 * Handler of command 'global_db node set'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_set(dap_chain_node_info_t *a_node_info, const char *a_alias_str, char **a_str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !a_alias_str) {
        set_reply_text(a_str_reply, "addr not found");
        return -1;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_address = com_global_db_get_addr(a_node_info, &a_node_info->hdr.address, a_alias_str);
    if(!l_address) {
        set_reply_text(a_str_reply, "alias not found");
        return -1;
    }
    // read node
    dap_chain_node_info_t *l_node_info_read = dap_chain_node_info_read(l_address, a_str_reply);
    if(!l_node_info_read) {
        DAP_DELETE(l_address);
        return -1;
    }
    // set cur node addr
    if(dap_db_set_cur_node_addr(l_node_info_read->hdr.address.uint64)) {
        set_reply_text(a_str_reply, "new address for node has been set");
        return 0;
    }
    set_reply_text(a_str_reply, "new address for node has not been set");
    return -1;
}

/**
 * Handler of command 'global_db node remote_set'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_set_remote(dap_chain_node_info_t *a_node_info, const char *a_alias_str, char **a_str_reply)
{
    if(!a_node_info->hdr.address.uint64 && !a_alias_str) {
        set_reply_text(a_str_reply, "addr not found");
        return -1;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_address = com_global_db_get_addr(a_node_info, &a_node_info->hdr.address, a_alias_str);
    if(!l_address) {
        set_reply_text(a_str_reply, "alias not found");
        return -1;
    }
    // read node
    dap_chain_node_info_t *l_node_info_read = dap_chain_node_info_read(l_address, a_str_reply);
    if(!l_node_info_read) {
        DAP_DELETE(l_address);
        return -1;
    }

    // get cur node addr
    uint64_t l_cur_node_addr = dap_db_get_cur_node_addr(); //0x12345
    if(!l_cur_node_addr) {
        set_reply_text(a_str_reply, "current node has no address");
        return -1;
    }
    dap_chain_node_info_t *l_node_info = dap_chain_node_info_read(l_address, a_str_reply);
    if(!l_node_info) {
        return -1;
    }
    // start connect
    dap_chain_node_client_t *client = dap_chain_node_client_connect(l_node_info);
    if(!client) {
        set_reply_text(a_str_reply, "can't connect");
        DAP_DELETE(l_node_info);
        return -1;
    }
    // wait connected
    int timeout_ms = 150000; //15 sec = 15000 ms
    int res = chain_node_client_wait(client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
    if(res != 1) {
        set_reply_text(a_str_reply, "no response from node");
        // clean client struct
        dap_chain_node_client_close(client);
        DAP_DELETE(l_node_info);
        return -1;
    }

    // send request
    res = dap_chain_node_client_send_chain_net_request(client, dap_stream_ch_chain_net_get_id(),
    STREAM_CH_CHAIN_NET_PKT_TYPE_SET_NODE_ADDR, (char*)&l_node_info->hdr.address.uint64, sizeof(uint64_t)); //, NULL);
    if(res != 1) {
        set_reply_text(a_str_reply, "no request sent");
        // clean client struct
        dap_chain_node_client_close(client);
        DAP_DELETE(l_node_info);
        return -1;
    }

    // wait for finishing of request
    timeout_ms = 9120000; // 2 min = 120 sec = 120 000 ms
    res = chain_node_client_wait(client, NODE_CLIENT_STATE_GET_NODE_ADDR, timeout_ms);
    DAP_DELETE(l_node_info);
    dap_client_disconnect(client->client);
    dap_chain_node_client_close(client);
    switch (res) {
    case 0:
        set_reply_text(a_str_reply, "timeout");
        return -1;
    case 1: {
        uint64_t addr = 0;
        if(client->recv_data_len == sizeof(uint64_t))
            memcpy(&addr, client->recv_data, sizeof(uint64_t));
        if(client->recv_data_len > 0)
            DAP_DELETE(client->recv_data);
        client->recv_data = NULL;
        set_reply_text(a_str_reply, "new address for remote node has been set 0x%x", addr);
    }
        return 0;
    default:
        set_reply_text(a_str_reply, "error");
        return -1;
    }

    set_reply_text(a_str_reply, "not implement");
    return -1;
}

/**
 * global_db command
 *
 * return 0 OK, -1 Err
 */
int com_global_db(int argc, const char ** argv, char **str_reply)
{
    enum {
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_LINK, CMD_DUMP, CMD_GET, CMD_SET, CMD_REMOTE_SET
    };
    //printf("com_global_db\n");
    int arg_index = 1;
    // find 'node' as first parameter only
    arg_index = find_option_val(argv, arg_index, min(argc, arg_index + 1), "node", NULL);
    if(!arg_index || argc < 3) {
        set_reply_text(str_reply, "parameters are not valid");
        return -1;
    }
    int arg_index_n = ++arg_index;
    // find command (add, delete, etc) as second parameter only
    int cmd_num = CMD_NONE;
    if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "add", NULL)) != 0) {
        cmd_num = CMD_ADD;
    }
    else if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "del", NULL)) != 0) {
        cmd_num = CMD_DEL;
    }
    else if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "link", NULL)) != 0) {
        cmd_num = CMD_LINK;
    }
    else if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "dump", NULL)) != 0) {
        cmd_num = CMD_DUMP;
    }
    else if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "get", NULL)) != 0) {
        cmd_num = CMD_GET;
    }
    else if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "set", NULL)) != 0) {
        cmd_num = CMD_SET;
    }
    else if((arg_index_n = find_option_val(argv, arg_index, min(argc, arg_index + 1), "remote_set", NULL)) != 0) {
        cmd_num = CMD_REMOTE_SET;
    }
    if(cmd_num == CMD_NONE) {
        set_reply_text(str_reply, "command %s not recognized", argv[1]);
        return -1;
    }
    //arg_index = arg_index_n; // no need, they are already equal must be
    assert(arg_index == arg_index_n);
    arg_index++;
    const char *addr_str = NULL, *alias_str = NULL, *shard_str = NULL, *link_str = NULL;
    const char *ipv4_str = NULL, *ipv6_str = NULL;
    // find addr, alias
    find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    find_option_val(argv, arg_index, argc, "-alias", &alias_str);
    find_option_val(argv, arg_index, argc, "-shard", &shard_str);
    find_option_val(argv, arg_index, argc, "-ipv4", &ipv4_str);
    find_option_val(argv, arg_index, argc, "-ipv6", &ipv6_str);
    find_option_val(argv, arg_index, argc, "-link", &link_str);

    // struct to write to the global db
    dap_chain_node_info_t node_info;
    dap_chain_node_addr_t link;
    memset(&node_info, 0, sizeof(dap_chain_node_info_t));
    memset(&link, 0, sizeof(dap_chain_node_addr_t));
    if(addr_str) {
        digit_from_string(addr_str, node_info.hdr.address.raw, sizeof(node_info.hdr.address.raw));
    }
    if(shard_str) {
        digit_from_string(shard_str, node_info.hdr.shard_id.raw, sizeof(node_info.hdr.shard_id.raw)); //DAP_CHAIN_SHARD_ID_SIZE);
    }
    if(link_str) {
        digit_from_string(link_str, link.raw, sizeof(link.raw));
    }

    switch (cmd_num)
    {
    // add new node to global_db
    case CMD_ADD:
        if(!arg_index || argc < 8) {
            set_reply_text(str_reply, "invalid parameters");
            return -1;
        }
        // handler of command 'global_db node add'
        return com_global_db_add(&node_info, alias_str, shard_str, ipv4_str, ipv6_str, str_reply);
        break;

    case CMD_DEL:
        // handler of command 'global_db node del'
        return com_global_db_del(&node_info, alias_str, str_reply);
        break;
    case CMD_LINK:
        if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "add", NULL))
            // handler of command 'global_db node link add -addr <node address> -link <node address>'
            return com_global_db_link(&node_info, "add", alias_str, &link, str_reply);
        else if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "del", NULL))
            // handler of command 'global_db node link del -addr <node address> -link <node address>'
            return com_global_db_link(&node_info, "del", alias_str, &link, str_reply);
        else {
            set_reply_text(str_reply, "command not recognize, supported format:\n"
                    "global_db node link <add|del] [-addr <node address>  | -alias <node alias>] -link <node address>");
            return -1;
        }
        break;
    case CMD_DUMP:
        // handler of command 'global_db node dump'
        return com_global_db_dump(&node_info, alias_str, str_reply);
        break;
    case CMD_GET:
        // handler of command 'global_db node get'
        return com_global_db_get(str_reply);
        break;
    case CMD_SET:
        // handler of command 'global_db node set'
        return com_global_db_set(&node_info, alias_str, str_reply);
        break;
    case CMD_REMOTE_SET:
        // handler of command 'global_db node remote_set'
        return com_global_db_set_remote(&node_info, alias_str, str_reply);
        break;

    default:
        set_reply_text(str_reply, "command %s not recognized", argv[1]);
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
    if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "handshake", NULL)) {
        cmd_num = CMD_HANDSHAKE;
    }
    else if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "connect", NULL)) {
        cmd_num = CMD_CONNECT;
    }
    else if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "alias", NULL)) {
        cmd_num = CMD_ALIAS;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        set_reply_text(str_reply, "command %s not recognized", argv[1]);
        return -1;
    }
    dap_chain_node_addr_t address;
    memset(&address, 0, sizeof(dap_chain_node_addr_t));
    const char *addr_str = NULL, *alias_str = NULL;
// find addr, alias
    find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    find_option_val(argv, arg_index, argc, "-alias", &alias_str);

    digit_from_string(addr_str, address.raw, sizeof(address.raw));

    switch (cmd_num)
    {
    // add alias
    case CMD_ALIAS:
        if(alias_str) {
            if(addr_str) {
                // add alias
                if(!add_alias(alias_str, &address))
                    log_it(L_WARNING, "can't save alias %s", alias_str);
                else {
                    set_reply_text(str_reply, "alias mapped successfully");
                }
            }
            else {
                set_reply_text(str_reply, "alias can't be mapped because -addr is not found");
                return -1;
            }
        }
        else {
            set_reply_text(str_reply, "alias can't be mapped because -alias is not found");
            return -1;
        }

        break;
        // make connect
    case CMD_CONNECT: {
        // get address from alias if addr not defined
        if(alias_str && !address.uint64) {
            dap_chain_node_addr_t *address_tmp = get_name_by_alias(alias_str);
            if(address_tmp) {
                memcpy(&address, address_tmp, sizeof(address_tmp));
                DAP_DELETE(address_tmp);
            }
            else {
                set_reply_text(str_reply, "no address found by alias");
                return -1;
            }
        }
        if(!address.uint64) {
            set_reply_text(str_reply, "addr not found");
            return -1;
        }

        // get cur node addr
        uint64_t l_cur_node_addr = dap_db_get_cur_node_addr(); //0x12345
        if(!l_cur_node_addr) {
            set_reply_text(str_reply, "node has no address");
            return -1;
        }

        /*// debug
         //if(0)
         {
         #include "dap_chain_global_db.h"
         size_t l_data_size_out = 0;
         dap_global_db_obj_t a_objs[2];
         a_objs[0].key = "k1";
         a_objs[1].key = "k2";
         a_objs[0].value = "v1";
         a_objs[0].value_len = strlen(a_objs[0].value);
         a_objs[1].value = "v2";
         a_objs[1].value_len = strlen(a_objs[1].value);
         dap_chain_global_db_save(a_objs, 2); //dap_chain_global_db_save
         char *l_diff = dap_db_log_get_diff(NULL);
         DAP_DELETE(l_diff);
         dap_global_db_obj_t **db1 = dap_chain_global_db_gr_load(GROUP_DATUM, &l_data_size_out);
         printf("GROUP_DATUM size = %d\n", l_data_size_out);
         dap_global_db_obj_t **db2 = dap_chain_global_db_gr_load(GROUP_ALIAS, &l_data_size_out);
         printf("GROUP_ALIAS size = %d\n", l_data_size_out);
         dap_global_db_obj_t **db3 = dap_chain_global_db_gr_load(GROUP_NODE, &l_data_size_out);
         printf("GROUP_NODE size = %d\n", l_data_size_out);
         //set_reply_text(str_reply, "debug ok");
         //return 0;
         }*/
        dap_chain_node_info_t *node_info = dap_chain_node_info_read(&address, str_reply);
        if(!node_info) {
            return -1;
        }
        // start connect
        dap_chain_node_client_t *client = dap_chain_node_client_connect(node_info);
        if(!client) {
            set_reply_text(str_reply, "can't connect");
            DAP_DELETE(node_info);
            return -1;
        }
        // wait connected
        int timeout_ms = 150000; //15 sec = 15000 ms
        int res = chain_node_client_wait(client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
        if(res != 1) {
            set_reply_text(str_reply, "no response from node");
            // clean client struct
            dap_chain_node_client_close(client);
            DAP_DELETE(node_info);
            return -1;
        }

        // send request
        size_t l_data_size_out = 0;
        // Get last timestamp in log
        time_t l_timestamp_start = dap_db_log_get_last_timestamp();
        size_t l_data_send_len = 0;
        uint8_t *l_data_send = dap_stream_ch_chain_net_make_packet(l_cur_node_addr, node_info->hdr.address.uint64,
                l_timestamp_start, NULL, 0, &l_data_send_len);

        uint8_t l_ch_id = dap_stream_ch_chain_net_get_id(); // Channel id for global_db sync
        res = dap_chain_node_client_send_chain_net_request(client, l_ch_id,
        STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC, l_data_send, l_data_send_len); //, NULL);
        DAP_DELETE(l_data_send);
        if(res != 1) {
            set_reply_text(str_reply, "no request sent");
            // clean client struct
            dap_chain_node_client_close(client);
            DAP_DELETE(node_info);
            return -1;
        }

        // wait for finishing of request
        timeout_ms = 9120000; // 2 min = 120 sec = 120 000 ms
        // TODO add progress info to console
        res = chain_node_client_wait(client, NODE_CLIENT_STATE_END, timeout_ms);
        DAP_DELETE(node_info);
        dap_client_disconnect(client->client);
        dap_chain_node_client_close(client);
        switch (res) {
        case 0:
            set_reply_text(str_reply, "timeout");
            return -1;
        case 1:
            set_reply_text(str_reply, "nodes sync completed");
            return 0;
        default:
            set_reply_text(str_reply, "error");
            return -1;
        }

    }
        break;
        // make handshake
    case CMD_HANDSHAKE: {
        // get address from alias if addr not defined
        if(alias_str && !address.uint64) {
            dap_chain_node_addr_t *address_tmp = get_name_by_alias(alias_str);
            if(address_tmp) {
                memcpy(&address, address_tmp, sizeof(address_tmp));
                DAP_DELETE(address_tmp);
            }
            else {
                set_reply_text(str_reply, "no address found by alias");
                return -1;
            }
        }
        if(!address.uint64) {
            set_reply_text(str_reply, "addr not found");
            return -1;
        }

        dap_chain_node_info_t *node_info = dap_chain_node_info_read(&address, str_reply);
        if(!node_info)
            return -1;
        int timeout_ms = 10000; //10 sec = 10000 ms
        // start handshake
        dap_chain_node_client_t *client = dap_chain_node_client_connect(node_info);
        if(!client) {
            set_reply_text(str_reply, "can't connect");
            DAP_DELETE(node_info);
            return -1;
        }
        // wait handshake
        int res = chain_node_client_wait(client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
        if(res != 1) {
            set_reply_text(str_reply, "no response from node");
            // clean client struct
            dap_chain_node_client_close(client);
            DAP_DELETE(node_info);
            return -1;
        }
        DAP_DELETE(node_info);

        //Add new established connection in the list
        int ret = chain_node_client_list_add(&address, client);
        switch (ret)
        {
        case -1:
            dap_chain_node_client_close(client);
            set_reply_text(str_reply, "connection established, but not saved");
            return -1;
        case -2:
            dap_chain_node_client_close(client);
            set_reply_text(str_reply, "connection already present");
            return -1;
        }
        set_reply_text(str_reply, "connection established");
    }
        break;
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
        set_reply_text(str_reply, "traceroute %s hops=%d time=%.1lf ms", addr, hops, time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                set_reply_text(str_reply, "traceroute %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case 2:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "Unknown traceroute module");
                break;
            case 3:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "first hop out of range");
                break;
            case 4:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "max hops cannot be more than 255");
                break;
            case 5:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "no more than 10 probes per hop");
                break;
            case 6:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "bad wait specifications");
                break;
            case 7:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "too big packetlen ");
                break;
            case 8:
                set_reply_text(str_reply, "traceroute %s error: %s", addr,
                        "IP version mismatch in addresses specified");
                break;
            case 9:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "bad sendtime");
                break;
            case 10:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "init_ip_options");
                break;
            case 11:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "calloc");
                break;
            case 12:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "parse cmdline");
                break;
            case 13:
                set_reply_text(str_reply, "traceroute %s error: %s", addr, "trace method's init failed");
                break;
            default:
                set_reply_text(str_reply, "traceroute %s error(%d) %s", addr, res, "trace not found");
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
            set_reply_text(str_reply, "tracepath %s hops=%d time=%.1lf ms", addr, hops, time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                set_reply_text(str_reply, "tracepath %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case ESOCKTNOSUPPORT:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't create socket");
                break;
            case 2:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IPV6_MTU_DISCOVER");
                break;
            case 3:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IPV6_RECVERR");
                break;
            case 4:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IPV6_HOPLIMIT");
                break;
            case 5:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IP_MTU_DISCOVER");
                break;
            case 6:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IP_RECVERR");
                break;
            case 7:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IP_RECVTTL");
                break;
            case 8:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "malloc");
                break;
            case 9:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IPV6_UNICAST_HOPS");
                break;
            case 10:
                set_reply_text(str_reply, "tracepath %s error: %s", addr, "Can't setsockopt IP_TTL");
                break;
            default:
                set_reply_text(str_reply, "tracepath %s error(%d) %s", addr, res, "trace not found");
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
        set_reply_text(str_reply, "host not specified");
        return -1;
    }
    const char *n_str = NULL;
    int argc_host = 1;
    int argc_start = 1;
    argc_start = find_option_val(argv, argc_start, argc, "-n", &n_str);
    if(argc_start) {
        argc_host = argc_start + 1;
        n = (n_str) ? atoi(n_str) : 4;
    }
    else {
        argc_start = find_option_val(argv, argc_start, argc, "-c", &n_str);
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
            set_reply_text(str_reply, "ping %s time=%.1lf ms", addr, res * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EDESTADDRREQ:
                set_reply_text(str_reply, "ping %s error: %s", addr, "Destination address required");
                break;
            case EADDRNOTAVAIL:
                set_reply_text(str_reply, "ping %s error: %s", (addr) ? addr : "",
                        (addr) ? "Host not found" : "Host not defined");
                break;
            case EPFNOSUPPORT:
                set_reply_text(str_reply, "ping %s error: %s", addr, "Unknown protocol family");
                break;
            default:
                set_reply_text(str_reply, "ping %s error(%d)", addr, -res);
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
        const COMMAND *cmd = find_command(argv[1]);
        if(cmd)
        {
            set_reply_text(str_reply, "%s:\n%s", cmd->doc, cmd->doc_ex);
            return 1;
        }
        set_reply_text(str_reply, "command \"%s\" not recognized", argv[1]);
        return -1;
    }
    else {
        // TODO Read list of commands & return it
    }
    if(str_reply)
        set_reply_text(str_reply, "command not defined, enter \"help <cmd name>\"");
    return -1;
}

/**
 * com_tx_create command
 *
 * Wallet info
 */
int com_tx_wallet(int argc, const char ** argv, char **str_reply)
{
    const char *c_wallets_path = "/opt/kelvin-node/etc";
    // Get address of wallet
    enum {
        CMD_NONE, CMD_WALLET_LIST, CMD_WALLET_INFO
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *cmd_str = NULL;
    // find  add parameter ('alias' or 'handshake')
    if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "list", NULL)) {
        cmd_num = CMD_WALLET_LIST;
    }
    else if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "info", NULL)) {
        cmd_num = CMD_WALLET_INFO;
    }
    arg_index++;
    if(cmd_num == CMD_NONE) {
        set_reply_text(str_reply, "format of command: wallet [list | info -addr <addr> -w <wallet_name>]");
        return -1;
    }

    dap_chain_node_addr_t address;
    memset(&address, 0, sizeof(dap_chain_node_addr_t));
    const char *addr_str = NULL, *wallet_name = NULL;
    // find wallet addr
    find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    find_option_val(argv, arg_index, argc, "-w", &wallet_name);

    dap_string_t *l_string_ret = dap_string_new(NULL);
    switch (cmd_num) {
    // wallet list
    case CMD_WALLET_LIST: {
        GDir *l_dir = g_dir_open(c_wallets_path, 0, NULL);
        if(l_dir) {
            const char *l_file = NULL;
            do {
                l_file = g_dir_read_name(l_dir);
                int l_file_len = (l_file) ? strlen(l_file) : 0;
                if(l_file_len > 8 && !g_strcmp0(l_file + l_file_len - 8, ".dwallet")) {
                    char *l_file_path_tmp = dap_strdup_printf("%s/%s", c_wallets_path, l_file);
                    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_file_path_tmp);
                    if(l_wallet) {
                        dap_chain_addr_t *l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet);
                        char *l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_addr);
                        dap_string_append_printf(l_string_ret, "\nwallet: %s\n", l_wallet->name);
                        dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");
                        DAP_DELETE(l_addr_str);
                        dap_chain_wallet_close(l_wallet);
                    }
                    DAP_DELETE(l_file_path_tmp);
                }
            }
            while(l_file);
            g_dir_close(l_dir);
        }
    }
        break;

        // wallet info
    case CMD_WALLET_INFO: {
        dap_chain_wallet_t *l_wallet = NULL;
        if(wallet_name)
            l_wallet = dap_chain_wallet_open(wallet_name, c_wallets_path);
        if(l_wallet) {
            dap_chain_addr_t *l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet);
            char *l_addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) l_addr);
            uint64_t balance = dap_chain_datum_tx_cache_calc_balance(l_addr);
            dap_string_append_printf(l_string_ret, "\nwallet: %s\n", l_wallet->name);
            dap_string_append_printf(l_string_ret, "addr: %s\n", (l_addr_str) ? l_addr_str : "-");
            dap_string_append_printf(l_string_ret, "balance: %lld\n", balance);
            DAP_DELETE(l_addr_str);
            dap_chain_wallet_close(l_wallet);
        }
        else {
            dap_string_free(l_string_ret, true);
            set_reply_text(str_reply, "wallet not found");
            return -1;
        }
    }
        break;
    }

    char *l_str_ret_tmp = dap_string_free(l_string_ret, false);
    char *str_ret = dap_strdup(l_str_ret_tmp);
    set_reply_text(str_reply, str_ret);
    DAP_DELETE(l_str_ret_tmp);
    return 0;
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
    const char *addr_base58_from = NULL;
    const char *addr_base58_to = NULL;
    const char *addr_base58_fee = NULL;
    const char *str_tmp = NULL;
    uint64_t value = 0;
    uint64_t value_fee = 0;
    find_option_val(argv, arg_index, argc, "from", &addr_base58_from);
    find_option_val(argv, arg_index, argc, "to", &addr_base58_to);
    if(find_option_val(argv, arg_index, argc, "fee", &addr_base58_fee)) {
        if(find_option_val(argv, arg_index, argc, "value_fee", &str_tmp)) {
            value_fee = strtoll(str_tmp, NULL, 10);
        }
    }
    if(find_option_val(argv, arg_index, argc, "value", &str_tmp)) {
        value = strtoll(str_tmp, NULL, 10);
    }
    if(!addr_base58_from) {
        set_reply_text(str_reply, "tx_create requires parameter 'from'");
        return -1;
    }
    if(!addr_base58_to) {
        set_reply_text(str_reply, "tx_create requires parameter 'to'");
        return -1;
    }
    if(!value) {
        set_reply_text(str_reply, "tx_create requires parameter 'value'");
        return -1;
    }
    if(addr_base58_fee && !value_fee) {
        set_reply_text(str_reply, "tx_create requires parameter 'value_fee' if 'fee' is specified");
        return -1;
    }

    const char *c_wallets_path = "/opt/kelvin-node/etc";
    const char *a_wallet_name_bliss = "w_bliss";
    const char *a_wallet_name_bliss2 = "w_bliss2";
    const char *a_wallet_name_picnic = "w_picnic";
    const char *a_wallet_name_tesla = "w_tesla";

    dap_chain_wallet_t *wallet_bliss = dap_chain_wallet_open(a_wallet_name_bliss, c_wallets_path);
    dap_chain_wallet_t *wallet_bliss2 = dap_chain_wallet_open(a_wallet_name_bliss2, c_wallets_path);
    dap_chain_wallet_t *wallet_picnic = dap_chain_wallet_open(a_wallet_name_picnic, c_wallets_path);
    dap_chain_wallet_t *wallet_tesla = dap_chain_wallet_open(a_wallet_name_tesla, c_wallets_path);
    dap_enc_key_t *l_key_bliss = dap_chain_wallet_get_key(wallet_bliss, 0);
    dap_enc_key_t *l_key_bliss2 = dap_chain_wallet_get_key(wallet_bliss2, 0);
    dap_enc_key_t *l_key_picnic = dap_chain_wallet_get_key(wallet_picnic, 0);
    dap_enc_key_t *l_key_tesla = dap_chain_wallet_get_key(wallet_tesla, 0);

    char *addr_w_bliss =
            //"EXh66KVCxChbKHQcTWKYJXhua6HVZecpxuTTmWGuqm1V4vy5mVq52wD8rMQvfUnmJHsL4MuoJ7YVSFqn2RrdoN19mqHP1aQXSQPnXDR6oP9vsBPwYC9PhSvAxFystX";
            "EXh66KVCxChbKHQcSCRnMTByuFRDU2UsZUViPz2BoUAEYYWPfu8WhHhqX9HSyL3U3Q54JvJoKRZhRtumsAVNV6j8pzgtZDkkwzLgHBCAQHcG2FaSwCxESjkCYkgHUo";
    char *addr_w_bliss2 =
            //"EXh66KVCxChbKHQcTeGf8TT7KhcCiiQ9TrPn6rcbNoNKuhAyJ4T9zr5yMfMCXGLVHmxVKZ6J4E9Zc7pNmAa4yrKNb3DkS34jxD6Q4MCXbHJMAPFEVtMoDdFMtCysE2";
            "EXh66KVCxChbKHQcSx27VwwbUnT2rRGNDBJm6zdC3DQw8XWtHqHrpoc9NEVd6Ub5rdFosQiXgWc5VhiNoySB6T4E49LMhMnLhr9sMSVqRr7Mix4bPrPEZXsYnNLzeX";
    char *addr_w_picnic =
            //"EXh66KVCxChbKJLxZbyNJLxfF8CfGZmdenQWuqtr8MnXavhJaLo6vckjpYgpcevBo3zB65sAGQJT3ctYVwQnASc6sYyaawFHnacsrcP47PB4XfLYiEDZvwog4AVdbC";
            "EXh66KVCxChbKJLxXTwipYMooUpoGvpwpkcjpmGLbubwzqR2vVsH9HEgT2LcU2hDs2BTFkaNC8itE8nuCWxskVtRJG4iaubBDcRWAt2awtCVHAULffQGrwe8ocRCzS";
    char *addr_w_tesla =
            "EXh66KVCxChbTZ9umzb4Y6nJcMti8DPUdrsE1V4adjoKyPG3VvyrzHh6wrP6wGERLq9Qj5qK4hMEjd6uidcbsSSpzKQuADC2g1DzYkCCcitAs2Nsxk4dhespDdximc";

    dap_chain_wallet_t *l_wallet;
    dap_enc_key_t *l_key;
    if(!strcmp(addr_base58_from, addr_w_bliss)) {
        l_wallet = wallet_bliss;
        l_key = l_key_bliss;
    }
    else if(!strcmp(addr_base58_from, addr_w_bliss2)) {
        l_wallet = wallet_bliss2;
        l_key = l_key_bliss2;
    }
    else if(!strcmp(addr_base58_from, addr_w_picnic)) {
        l_wallet = wallet_picnic;
        l_key = l_key_picnic;
    }
    if(!l_wallet || !l_key) {
        set_reply_text(str_reply, "wallet for address 'from' does not exist");
        return -1;
    }

    dap_chain_addr_t *addr_from = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet);
    dap_chain_addr_t *addr_to = dap_chain_str_to_addr(addr_base58_to);
    dap_chain_addr_t *addr_fee = dap_chain_str_to_addr(addr_base58_fee);

    if(!addr_from) {
        set_reply_text(str_reply, "source address is invalid");
        return -1;
    }
    if(!addr_to) {
        set_reply_text(str_reply, "destination address is invalid");
        return -1;
    }
    if(addr_base58_fee && !addr_fee) {
        set_reply_text(str_reply, "fee address is invalid");
        return -1;
    }
    /*    dap_chain_addr_t *addr_b2 = (dap_chain_addr_t *) dap_chain_wallet_get_addr(wallet_bliss2);
     dap_chain_addr_t *addr_p = (dap_chain_addr_t *) dap_chain_wallet_get_addr(wallet_picnic);
     dap_chain_addr_t *addr_t = (dap_chain_addr_t *) dap_chain_wallet_get_addr(wallet_tesla);

     char *addr_str_b2 = dap_chain_addr_to_str((dap_chain_addr_t*) addr_b2);
     char *addr_str_p = dap_chain_addr_to_str((dap_chain_addr_t*) addr_p);
     char *addr_str_t = dap_chain_addr_to_str((dap_chain_addr_t*) addr_t);

     char *addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) addr_from);
     const dap_chain_addr_t *addr2 = dap_chain_str_to_addr(addr_str);
     char *addr_str2 = dap_chain_addr_to_str(addr2);
     int a1 = strcmp(addr_str, addr_str2);
     int a2 = strcmp(addr_str, addr_w_bliss);
     int a3 = strcmp(addr_str, addr_w_bliss2);*/

    static bool l_first_start = true;
    if(l_first_start)
    {
        const char *l_token_name = "KLVN";
        dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet_bliss, 0);
        const dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(wallet_bliss);
        dap_chain_node_datum_tx_cache_init(l_key, l_token_name, (dap_chain_addr_t*) l_addr, 1000);
        l_first_start = false;
    }
    dap_string_t *string_ret = dap_string_new(NULL);
    //g_string_printf(string_ret, "from=%s\nto=%s\nval=%lld\nfee=%s\nval_fee=%lld\n\n",
    //        addr_base58_from, addr_base58_to, value, addr_base58_fee, value_fee);

    uint64_t balance2 = dap_chain_datum_tx_cache_calc_balance(addr_to);
    uint64_t balance3 = dap_chain_datum_tx_cache_calc_balance(addr_fee);
    uint64_t balance1 = dap_chain_datum_tx_cache_calc_balance(addr_from);
    dap_string_append_printf(string_ret, "transactions in cache=%d balance w_from=%lld w_to=%lld w_feee=%lld\n",
            dap_chain_node_datum_tx_cache_count(),
            balance1, balance2, balance3);

    int res = dap_chain_datum_tx_ctrl_create_transfer(l_key, addr_from, addr_to, addr_fee, value, value_fee);
    dap_string_append_printf(string_ret, "transfer=%s\n", (res == 1) ? "Ok" : "False");

    if(1) {
        uint64_t balance1 = dap_chain_datum_tx_cache_calc_balance(addr_from);
        uint64_t balance2 = dap_chain_datum_tx_cache_calc_balance(addr_to);
        uint64_t balance3 = dap_chain_datum_tx_cache_calc_balance(addr_fee);
        dap_string_append_printf(string_ret, "transactions in cache=%d balance w_from=%lld w_to=%lld w_feee=%lld\n",
                dap_chain_node_datum_tx_cache_count(),
                balance1, balance2, balance3);
    }

    char *str_ret_tmp = dap_string_free(string_ret, false);
    char *str_ret = strdup(str_ret_tmp);
    set_reply_text(str_reply, str_ret);

    DAP_DELETE(str_ret_tmp);
    DAP_DELETE(addr_to);
    DAP_DELETE(addr_fee);
    dap_chain_wallet_close(wallet_bliss);
    dap_chain_wallet_close(wallet_bliss2);
    dap_chain_wallet_close(wallet_picnic);
    dap_chain_wallet_close(wallet_tesla);
    return 0;
}

/**
 * com_tx_create command
 *
 * Signing transaction
 */
int com_tx_create0(int argc, const char ** argv, char **str_reply)
{
    // create wallet
    const char *a_wallets_path = "/opt/kelvin-node/etc";
    const char *a_wallet_name_bliss = "w_bliss";
    const char *a_wallet_name_bliss2 = "w_bliss2";
    const char *a_wallet_name_picnic = "w_picnic";
    const char *a_wallet_name_tesla = "w_tesla";

    dap_chain_net_id_t a_net_id = { 0x1 };
    dap_chain_sign_type_t a_sig_type = { SIG_TYPE_TESLA };
    //dap_chain_sign_type_t a_sig_type = { SIG_TYPE_PICNIC };
    //dap_chain_sign_type_t a_sig_type = { SIG_TYPE_BLISS };
    const char * a_wallet_name = a_wallet_name_tesla;
    dap_chain_wallet_t *wallet0 = dap_chain_wallet_create(a_wallet_name, a_wallets_path, a_net_id, a_sig_type);

    dap_chain_wallet_t *wallet_bliss = dap_chain_wallet_open(a_wallet_name_bliss, a_wallets_path);
    dap_chain_wallet_t *wallet_bliss2 = dap_chain_wallet_open(a_wallet_name_bliss2, a_wallets_path);
    dap_chain_wallet_t *wallet_picnic = dap_chain_wallet_open(a_wallet_name_picnic, a_wallets_path);
    dap_chain_wallet_t *wallet_tesla = dap_chain_wallet_open(a_wallet_name_tesla, a_wallets_path);
    dap_enc_key_t *l_key_bliss = dap_chain_wallet_get_key(wallet_bliss, 0);
    dap_enc_key_t *l_key_bliss2 = dap_chain_wallet_get_key(wallet_bliss2, 0);
    dap_enc_key_t *l_key_picnic = dap_chain_wallet_get_key(wallet_picnic, 0);
    dap_enc_key_t *l_key_tesla = dap_chain_wallet_get_key(wallet_tesla, 0);
    /*/ debug - test check signing
     {


     int a_data_size = 50;
     char *a_data = "DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify";

     dap_enc_key_t *l_key0 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_BLISS, NULL, 0, NULL, 0, 0);
     dap_enc_key_t *l_key1 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_TESLA, NULL, 0, NULL, 0, 0);
     dap_enc_key_t *l_key2 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_PICNIC, NULL, 0, NULL, 0, 0);
     dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet, 0);

     size_t l_buflen_out;
     char *l_data;
     l_data = dap_enc_key_serealize_pub_key(l_key0, &l_buflen_out);
     dap_enc_key_deserealize_pub_key(l_key0, l_data, l_buflen_out);
     l_data = dap_enc_key_serealize_pub_key(l_key1, &l_buflen_out);
     dap_enc_key_deserealize_pub_key(l_key1, l_data, l_buflen_out);
     l_data = dap_enc_key_serealize_pub_key(l_key2, &l_buflen_out);
     dap_enc_key_deserealize_pub_key(l_key2, l_data, l_buflen_out);
     l_data = dap_enc_key_serealize_pub_key(l_key, &l_buflen_out);
     dap_enc_key_deserealize_pub_key(l_key, l_data, l_buflen_out);

     dap_chain_sign_t *l_chain_sign;
     l_chain_sign = dap_chain_sign_create(l_key0, a_data, a_data_size, 0);
     int l_size0 = dap_chain_sign_get_size(l_chain_sign);
     int l_verify0 = dap_chain_sign_verify(l_chain_sign, a_data, a_data_size);
     DAP_DELETE(l_chain_sign);
     l_chain_sign = dap_chain_sign_create(l_key1, a_data, a_data_size, 0);
     int l_size1 = dap_chain_sign_get_size(l_chain_sign);
     int l_verify1 = dap_chain_sign_verify(l_chain_sign, a_data, a_data_size);
     DAP_DELETE(l_chain_sign);
     l_chain_sign = dap_chain_sign_create(l_key2, a_data, a_data_size, 0);
     int l_size2 = dap_chain_sign_get_size(l_chain_sign);
     int l_verify2 = dap_chain_sign_verify(l_chain_sign, a_data, a_data_size);
     DAP_DELETE(l_chain_sign);
     l_chain_sign = dap_chain_sign_create(l_key, a_data, a_data_size, 0);
     int l_size = dap_chain_sign_get_size(l_chain_sign);
     int l_verify = dap_chain_sign_verify(l_chain_sign, a_data, a_data_size);
     DAP_DELETE(l_chain_sign);
     printf("verify=%d/%d %d/%d %d/%d %d/%d\n", l_size0, l_verify0, l_size1, l_verify1, l_size2, l_verify2, l_size,
     l_verify);

     dap_enc_key_delete(l_key0);
     dap_enc_key_delete(l_key1);
     dap_enc_key_delete(l_key2);
     }*/

    static bool l_first_start = true;
    if(l_first_start)
    {
        const char *l_token_name = "KLVN";
        dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet_bliss, 0);
        const dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(wallet_bliss);
        dap_chain_node_datum_tx_cache_init(l_key, l_token_name, (dap_chain_addr_t*) l_addr, 1000);
        l_first_start = false;
    }
    int res;
    // transfer from 1st transaction to addr_w_bliss
    /*    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
     dap_chain_hash_fast_t l_tx_prev_hash = { 0 };
     uint32_t l_tx_out_prev_idx = 0;
     dap_chain_tx_in_t *l_tx_item_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, l_tx_out_prev_idx);
     res = dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *) l_tx_item_in);
     res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
     res = dap_chain_node_datum_tx_cache_add(l_tx);
     DAP_DELETE(l_tx);*/

    char *addr_w_bliss =
            "EXh66KVCxChbKHQcTWKYJXhua6HVZecpxuTTmWGuqm1V4vy5mVq52wD8rMQvfUnmJHsL4MuoJ7YVSFqn2RrdoN19mqHP1aQXSQPnXDR6oP9vsBPwYC9PhSvAxFystX";
    char *addr_w_bliss2 =
            "EXh66KVCxChbKHQcTeGf8TT7KhcCiiQ9TrPn6rcbNoNKuhAyJ4T9zr5yMfMCXGLVHmxVKZ6J4E9Zc7pNmAa4yrKNb3DkS34jxD6Q4MCXbHJMAPFEVtMoDdFMtCysE2";
    char *addr_w_picnic =
            "EXh66KVCxChbKJLxZbyNJLxfF8CfGZmdenQWuqtr8MnXavhJaLo6vckjpYgpcevBo3zB65sAGQJT3ctYVwQnASc6sYyaawFHnacsrcP47PB4XfLYiEDZvwog4AVdbC";

    dap_chain_addr_t *addr_1 = (dap_chain_addr_t *) dap_chain_wallet_get_addr(wallet_bliss);
    dap_chain_addr_t *addr_2 = dap_chain_str_to_addr(addr_w_bliss2);
    dap_chain_addr_t *addr_3 = dap_chain_str_to_addr(addr_w_picnic);

    //char *addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) addr_from);
    //const dap_chain_addr_t *addr2 = dap_chain_str_to_addr(addr_str);
    //char *addr_str2 = dap_chain_addr_to_str(addr2);
    //int a = strcmp(addr_str,addr_str2);

    uint64_t balance1 = dap_chain_datum_tx_cache_calc_balance(addr_1);
    uint64_t balance2 = dap_chain_datum_tx_cache_calc_balance(addr_2);
    uint64_t balance3 = dap_chain_datum_tx_cache_calc_balance(addr_3);
    printf("transactions in cache=%d balance %lld %lld %lld\n", dap_chain_node_datum_tx_cache_count(),
            balance1, balance2, balance3);

    res = dap_chain_datum_tx_ctrl_create_transfer(l_key_bliss, addr_1, addr_2, addr_3, 100, 2);
    printf("transfer=%d\n", res);
    balance1 = dap_chain_datum_tx_cache_calc_balance(addr_1);
    balance2 = dap_chain_datum_tx_cache_calc_balance(addr_2);
    balance3 = dap_chain_datum_tx_cache_calc_balance(addr_3);
    printf("transactions in cache=%d balance %lld %lld %lld\n", dap_chain_node_datum_tx_cache_count(),
            balance1, balance2, balance3);

    res = dap_chain_datum_tx_ctrl_create_transfer(l_key_bliss2, addr_2, addr_3, addr_3, 200, 2);
    printf("transfer=%d\n", res);
    balance1 = dap_chain_datum_tx_cache_calc_balance(addr_1);
    balance2 = dap_chain_datum_tx_cache_calc_balance(addr_2);
    balance3 = dap_chain_datum_tx_cache_calc_balance(addr_3);
    printf("transactions in cache=%d balance %lld %lld %lld\n", dap_chain_node_datum_tx_cache_count(),
            balance1, balance2, balance3);

    dap_chain_wallet_close(wallet_bliss);
    dap_chain_wallet_close(wallet_bliss2);
    dap_chain_wallet_close(wallet_picnic);
    dap_chain_wallet_close(wallet_tesla);
    set_reply_text(str_reply, "com_tx_create ok");
    return 0;

    /*/dap_chain_datum_tx_vefify(l_tx);

     char *addr_w_tesla = "ad8VdHszE1zxS2SDFsvTsmQVBh1G7exkvPy6DiUtjzpgiGY82iMaWeP83K6Euh9fih2G3WN1E6SpfWdCfxA7yjyTu3yrw";
     char *addr_w_picnic =
     "ad8VdHszE1zx5WVKbKugtuBAimU3QT5FCnWMKKaYpMmeRwTwTNULiM7eyYiBskEG9LSN5NCp5roadQtCXe4caJqKPcWiB";
     char *addr_w_bliss = "ad8VdHszE1zx5UAFyPFYryPdMiXPMeQDL5gy6jUztE6NJsTN4idtU4xtKHkknXBYfoXQUJDUYHkL5B2QDgyisdQ715hnF";
     const dap_chain_addr_t *addr = dap_chain_wallet_get_addr(wallet);


     dap_chain_datum_tx_t *l_tx_tmp = dap_chain_node_datum_tx_cache_find_by_pkey(l_key->pub_key_data,
     l_key->pub_key_data_size, NULL);

     char *addr_str = dap_chain_addr_to_str((dap_chain_addr_t*) addr);
     const dap_chain_addr_t *addr2 = dap_chain_str_to_addr(addr_str);
     char *addr_str2 = dap_chain_addr_to_str(addr2);
     free(addr_str);
     free(addr_str2);

     if(wallet) {
     if(dap_chain_wallet_get_certs_number(wallet) > 0) {
     dap_chain_pkey_t *pk0 = dap_chain_wallet_get_pkey(wallet, 0);
     dap_enc_key_t *a_key = dap_chain_wallet_get_key(wallet, 0);
     //dap_enc_key_t *a_key1 = dap_chain_wallet_get_key(wallet, 0);
     //dap_enc_key_t *a_key2 = dap_chain_wallet_get_key(wallet2, 0);

     int res = dap_chain_datum_tx_add_item(&l_tx, l_tx_item_in);
     int res1 = dap_chain_datum_tx_add_sign(&l_tx, a_key);
     int res2 = dap_chain_datum_tx_add_sign(&l_tx, a_key);
     int res3 = dap_chain_datum_tx_verify_sign(l_tx);
     res3 = 0;
     }
     dap_chain_wallet_close(wallet);
     DAP_DELETE(l_tx);
     }
     set_reply_text(str_reply, "com_tx_create ok");
     return 0;*/
}

/**
 * tx_verify command
 *
 * Verifing transaction
 */
int com_tx_verify(int argc, const char ** argv, char **str_reply)
{
    if(argc > 1) {
        const COMMAND *cmd = find_command(argv[1]);
        if(cmd)
        {
            if(str_reply)
                *str_reply = dap_strdup(cmd->doc);
            return 1;
        }
        if(str_reply)
            set_reply_text(str_reply, "command \"%s\" not recognized", argv[1]);
    }
    if(str_reply)
        set_reply_text(str_reply, "command not defined, enter \"help <cmd name>\"");
    return -1;
}

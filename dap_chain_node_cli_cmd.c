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
//#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_wallet.h"
#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_remote.h"
#include "dap_chain_node_cli_cmd.h"

#include "dap_chain_datum.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_chain_datum_tx_cache.h"

// Max and min macros
#define max(a,b)              ((a) > (b) ? (a) : (b))
#define min(a,b)              ((a) < (b) ? (a) : (b))

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
    char a_value[2 * sizeof(dap_chain_node_addr_t) + 1];
    if(bin2hex(a_value, (const unsigned char *) addr, sizeof(dap_chain_node_addr_t)) == -1)
        return false;
    a_value[2 * sizeof(dap_chain_node_addr_t)] = '\0';
    bool res = dap_chain_global_db_gr_set(a_key, a_value, GROUP_ALIAS);
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
dap_chain_node_addr_t* get_name_by_alias(const char *alias)
{
    dap_chain_node_addr_t *addr = NULL;
    if(!alias)
        return NULL;
    const char *a_key = alias;
    char *addr_str = dap_chain_global_db_gr_get(a_key, GROUP_ALIAS);
    if(addr_str && strlen(addr_str) == sizeof(dap_chain_node_addr_t) * 2) {
        addr = DAP_NEW_Z(dap_chain_node_addr_t);
        if(hex2bin((char*) addr, (const unsigned char *) addr_str, sizeof(dap_chain_node_addr_t) * 2) == -1) {
            DAP_DELETE(addr);
            addr = NULL;
        }
    }
    DAP_DELETE(addr_str);
    return addr;
}

/**
 * Find in base alias by addr
 *
 * return list of addr, NULL if not found
 */
static GList* get_aliases_by_name(dap_chain_node_addr_t *addr)
{
    if(!addr)
        return NULL;
    GList *list_aliases = NULL;
    size_t data_size = 0;
    // read all aliases
    dap_global_db_obj_t **objs = dap_chain_global_db_gr_load(&data_size, GROUP_ALIAS);
    if(!objs || !data_size)
        return NULL;
    for(int i = 0; i < data_size; i++) {
        dap_chain_node_addr_t addr_i;
        dap_global_db_obj_t *obj = objs[i];
        if(!obj)
            break;
        char *addr_str = obj->value;
        if(addr_str && strlen(addr_str) == sizeof(dap_chain_node_addr_t) * 2) {
            //addr_i = DAP_NEW_Z(dap_chain_node_addr_t);
            if(hex2bin((char*) &addr_i, (const unsigned char *) addr_str, sizeof(dap_chain_node_addr_t) * 2) == -1) {
                continue;
            }
            if(addr->uint64 == addr_i.uint64) {
                list_aliases = g_list_prepend(list_aliases, strdup(obj->key));
            }
        }
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
            g_free(*str_reply);
            *str_reply = NULL;
        }
        va_list args;
        va_start(args, str);
        *str_reply = g_strdup_vprintf(str, args); //*str_reply = g_strdup(str);
        va_end(args);
    }
}

/**
 * Read node from base
 */
static dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_node_addr_t *address, char **str_reply)
{
    char *a_key = com_global_db_get_key_for_addr(address);
    if(!a_key)
    {
        set_reply_text(str_reply, "can't calculate hash of addr");
        return NULL;
    }
    // read node
    char *str = dap_chain_global_db_gr_get(a_key, GROUP_NODE);
    if(!str) {
        set_reply_text(str_reply, "node not found in base");
        DAP_DELETE(a_key);
        return NULL;
    }
    dap_chain_node_info_t *node_info = dap_chain_node_info_deserialize(str, (str) ? strlen(str) : 0);
    if(!node_info) {
        set_reply_text(str_reply, "node has invalid format in base");
    }
    DAP_DELETE(str);
    DAP_DELETE(a_key);
    return node_info;
}

/**
 * Save node from base
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
    char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    bool res = dap_chain_global_db_gr_set(a_key, a_value, GROUP_NODE);
    DAP_DELETE(a_key);
    DAP_DELETE(a_value);
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
                GList *list_aliases = get_aliases_by_name(address);
                GList *list = list_aliases;
                while(list)
                {
                    const char *alias = (const char *) list->data;
                    del_alias(alias);
                    list = g_list_next(list);
                }
                g_list_free_full(list_aliases, (GDestroyNotify) free);
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
static int com_global_db_dump(dap_chain_node_info_t *node_info, const char *alias_str, char **str_reply)
{
    char *a_key = NULL;
    if(!node_info->hdr.address.uint64 && !alias_str) {
        set_reply_text(str_reply, "addr not found");
        return -1;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, &node_info->hdr.address, alias_str);
    if(!address) {
        set_reply_text(str_reply, "alias not found");
        return -1;
    }
    // read node
    dap_chain_node_info_t *node_info_read = dap_chain_node_info_read(address, str_reply);
    if(!node_info_read) {
        DAP_DELETE(address);
        return -1;
    }

    int hostlen = 128;
    char host4[hostlen];
    char host6[hostlen];
    struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = node_info_read->hdr.ext_addr_v4 };
    const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, hostlen);

    struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = node_info_read->hdr.ext_addr_v6 };
    const char* str_ip6 = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host6, hostlen);

    // get aliases in form of string
    GString *aliases_string = g_string_new(NULL);
    GList *list_aliases = get_aliases_by_name(address);
    if(list_aliases)
    {
        GList *list = list_aliases;
        while(list)
        {
            const char *alias = (const char *) list->data;
            g_string_append_printf(aliases_string, "\nalias %s", alias);
            list = g_list_next(list);
        }
        g_list_free_full(list_aliases, (GDestroyNotify) free);
    }
    else
        g_string_append(aliases_string, "\nno aliases");

    // get links in form of string
    GString *links_string = g_string_new(NULL);
    for(int i = 0; i < node_info_read->hdr.links_number; i++) {
        dap_chain_node_addr_t link_addr = node_info_read->links[i];
        g_string_append_printf(links_string, "\nlink%02d address : 0x%llx", i, link_addr.uint64);
    }

    // set full reply with node param
    set_reply_text(str_reply, "node address 0x%llx\nshard 0x%llx%s\nipv4 %s\nipv6 %s\nnumber of links %d%s",
            node_info_read->hdr.address, node_info_read->hdr.shard_id, aliases_string->str,
            str_ip4, str_ip6,
            node_info_read->hdr.links_number, links_string->str);
    g_string_free(aliases_string, TRUE);
    g_string_free(links_string, TRUE);

    DAP_DELETE(address);
    DAP_DELETE(node_info_read);

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
        CMD_NONE, CMD_ADD, CMD_DEL, CMD_LINK, CMD_DUMP
    };
    printf("com_global_db\n");
    int arg_index = 1;
    // find 'node' as first parameter only
    arg_index = find_option_val(argv, arg_index, min(argc, arg_index + 1), "node", NULL);
    if(!arg_index || argc < 4) {
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
        CMD_NONE, CMD_ALIAS, CMD_HANDSHAKE
    };
    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *cmd_str = NULL;
// find  add parameter ('alias' or 'handshake')
    if(find_option_val(argv, arg_index, min(argc, arg_index + 1), "handshake", NULL)) {
        cmd_num = CMD_HANDSHAKE;
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

        // make handshake
    case CMD_HANDSHAKE:
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
        if(!node_info) {
            return -1;
        }
        int timeout_ms = 10000; //10 sec.
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
    const char *addr = NULL;
    int n = 4;
    if(argc > 1)
        addr = argv[1];
    const char *n_str = NULL;
    if(find_option_val(argv, 2, argc, "-n", &n_str))
        n = (n_str) ? atoi(n_str) : 4;
    else if(find_option_val(argv, 2, argc, "-c", &n_str))
        n = (n_str) ? atoi(n_str) : 4;
    if(n <= 1)
        n = 1;
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

dap_chain_datum_tx_t* create_tx(const char *net_name)
{
    dap_chain_tx_in_t tx_in;
    dap_chain_tx_in_t tx_out;

    tx_in.header.type = TX_ITEM_TYPE_IN;
    //tx_in.header.sig_size = 0;
    //tx_in

    dap_chain_datum_tx_t *tx = DAP_NEW_Z(dap_chain_datum_tx_t);
    tx->header.lock_time = time(NULL);
    int res = dap_chain_datum_tx_add_item(&tx, (const uint8_t*) &tx_in);
    //dap_chain_tx_in_t

    //dap_chain_hash_t a_hash_fast;
    //dap_hash((char*) tx, sizeof(tx), a_hash_fast.raw, sizeof(a_hash_fast.raw), DAP_HASH_TYPE_KECCAK);

    /*
     // create file with dap_chain_t
     dap_chain_id_t a_chain_id = {0x1};
     dap_chain_net_id_t a_chain_net_id = {0x2};
     dap_chain_shard_id_t a_shard_id = {0x3};

     dap_chain_t *a_chain = dap_chain_create(a_chain_net_id, a_chain_id, a_shard_id);
     const char * a_chain_net_name = "0x1";
     const char * a_chain_cfg_name = "chain-0";
     dap_chain_t *ch2 =  dap_chain_load_from_cfg(a_chain_net_name, a_chain_cfg_name);

     //dap_chain_net_t *l_net = dap_chain_net_by_name(net_name);
     //dap_chain_id_t *chain = l_net->pub.chains;
     */
    return tx;
}

/**
 * com_tx_create command
 *
 * Signing transaction
 */
int com_tx_create(int argc, const char ** argv, char **str_reply)
{
    // create wallet
    const char *a_wallets_path = "/opt/kelvin-node/etc";
    const char *a_wallet_name = "w1";
    dap_chain_net_id_t a_net_id = { 0x1 };
    dap_chain_sign_type_t a_sig_type = { SIG_TYPE_TESLA };
    //dap_chain_sign_type_t a_sig_type = { SIG_TYPE_PICNIC };
    //dap_chain_sign_type_t a_sig_type = { SIG_TYPE_BLISS };
    dap_chain_wallet_t *wallet = dap_chain_wallet_create(a_wallet_name, a_wallets_path, a_net_id, a_sig_type);
    dap_chain_wallet_t *wallet2 = dap_chain_wallet_open(a_wallet_name, a_wallets_path);
    //wallet = dap_chain_wallet_open(a_wallet_name, a_wallets_path);
    //dap_chain_wallet_save(wallet2);
    dap_chain_datum_tx_t *tx = create_tx("0x123");

    static bool l_first_start = true;
    if(l_first_start)
    {
        const char *l_token_name = "KLVN";
        dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet, 0);
        const dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(wallet);
        dap_chain_node_datum_tx_cache_init(l_key, l_token_name, (dap_chain_addr_t*)l_addr, 1000);
        l_first_start = false;
    }

    const dap_chain_addr_t *addr = dap_chain_wallet_get_addr(wallet);

    char *addr_str = dap_chain_addr_to_str((dap_chain_addr_t*)addr);
    const dap_chain_addr_t *addr2 = dap_chain_str_to_addr(addr_str);
    char *addr_str2 = dap_chain_addr_to_str(addr2);
    free(addr_str);

    // debug - check signing
    {
        int a_data_size = 50;
        char *a_data = "DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify";


        dap_enc_key_t *a_key0 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_BLISS, NULL, 0, NULL, 0, 0);

        dap_enc_key_t *a_key1 = dap_chain_wallet_get_key(wallet, 0);
        dap_enc_key_t *a_key2 = dap_chain_wallet_get_key(wallet2, 0);
        dap_chain_sign_t *a_chain_sign0 = dap_chain_sign_create(a_key0, a_data, a_data_size, 0);
        dap_chain_sign_t *a_chain_sign1 = dap_chain_sign_create(a_key1, a_data, a_data_size, 0);
        dap_chain_sign_t *a_chain_sign2 = dap_chain_sign_create(a_key2, a_data, a_data_size, 0);
        size_t a_chain_sign_size = dap_chain_sign_get_size(a_chain_sign1);
        int verify0 = dap_chain_sign_verify(a_chain_sign0, a_data, a_data_size);
        int verify1 = dap_chain_sign_verify(a_chain_sign1, a_data, a_data_size);
        int verify2 = dap_chain_sign_verify(a_chain_sign2, a_data, a_data_size);
        printf("a_chain_sign=%d verify=%d %d %d\n", a_chain_sign_size, verify0, verify1, verify2);
        free(a_chain_sign2);
        free(a_chain_sign1);
        free(a_chain_sign0);
        //dap_enc_key_delete(a_key2);
        dap_enc_key_delete(a_key0);
        //dap_enc_key_delete(a_key1);
    }

    if(wallet) {
        if(dap_chain_wallet_get_certs_number(wallet) > 0) {
            dap_chain_pkey_t *pk0 = dap_chain_wallet_get_pkey(wallet, 0);
            dap_enc_key_t *a_key = dap_chain_wallet_get_key(wallet, 0);
            //dap_enc_key_t *a_key1 = dap_chain_wallet_get_key(wallet, 0);
            //dap_enc_key_t *a_key2 = dap_chain_wallet_get_key(wallet2, 0);
            int res = dap_chain_datum_tx_add_sign(&tx, a_key);
            int res1 = dap_chain_datum_tx_add_sign(&tx, a_key);
            int res2 = dap_chain_datum_tx_add_sign(&tx, a_key);
            int res3 = dap_chain_datum_tx_verify_sign(tx);
            res3 = 0;
        }
        dap_chain_wallet_close(wallet);
        DAP_DELETE(tx);
    }
    set_reply_text(str_reply, "com_tx_create ok");
    return 0;
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
                *str_reply = g_strdup(cmd->doc);
            return 1;
        }
        if(str_reply)
            set_reply_text(str_reply, "command \"%s\" not recognized", argv[1]);
    }
    if(str_reply)
        set_reply_text(str_reply, "command not defined, enter \"help <cmd name>\"");
    return -1;
}

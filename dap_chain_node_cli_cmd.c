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
#include <glib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "iputils/iputils.h"
//#include "dap_common.h"
#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_cli_cmd.h"

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
static dap_chain_node_addr_t* get_name_by_alias(const char *alias)
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
 * return addr, NULL if not found
 */
static char* get_alias_by_name(dap_chain_node_addr_t *addr)
{
    if(!addr)
        return NULL;
    char *alias = NULL;
    const char *a_key = alias;
    size_t data_size = 0;
    // read all aliases
    dap_global_db_obj_t **aliases_list = dap_chain_global_db_gr_load(&data_size, GROUP_ALIAS);
    if(!aliases_list || !data_size)
        return NULL;
    for(int i = 0; i < data_size; i++) {
        dap_chain_node_addr_t addr_i;
        dap_global_db_obj_t *obj = aliases_list[i];
        if(!obj)
            break;
        char *addr_str = obj->value;
        if(addr_str && strlen(addr_str) == sizeof(dap_chain_node_addr_t) * 2) {
            addr = DAP_NEW_Z(dap_chain_node_addr_t);
            if(hex2bin((char*) &addr_i, (const unsigned char *) addr_str, sizeof(dap_chain_node_addr_t) * 2) == -1) {
                continue;
            }
        }
        if(addr->uint64 == addr_i.uint64) {
            alias = strdup(obj->key);
            break;
        }
    }
    dap_chain_global_db_objs_delete(aliases_list);
    return alias;
}

static dap_chain_node_addr_t* com_global_db_get_addr(dap_chain_node_info_t *node_info,
        const char *addr_str, const char *alias_str)
{
    dap_chain_node_addr_t *address = NULL;
    if(alias_str && !addr_str) {
        address = get_name_by_alias(alias_str);
    }
    if(addr_str) {
        address = DAP_NEW(dap_chain_node_addr_t);
        address->uint64 = node_info->hdr.address.uint64;
    }
    return address;
}

static char* com_global_db_get_key_for_addr(dap_chain_node_addr_t *address)
{
    char *a_key = dap_chain_global_db_hash((const uint8_t*) address, sizeof(dap_chain_node_addr_t));
    return a_key;
}

/**
 * Handler of command 'global_db node add'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_add(dap_chain_node_info_t *node_info, const char *addr_str, const char *alias_str,
        const char *shard_str, const char *ipv4_str, const char *ipv6_str, char **str_reply)
{

    if(!addr_str) {
        if(str_reply)
            *str_reply = g_strdup("not found -addr parameter");
        return -1;
    }
    if(!shard_str) {
        if(str_reply)
            *str_reply = g_strdup("not found -shard parameter");
        return -1;
    }
    if(!ipv4_str && !ipv6_str) {
        if(str_reply)
            *str_reply = g_strdup("not found -ipv4 or -ipv6 parameter");
        return -1;
    }
    else {
        if(ipv4_str)
            inet_pton(AF_INET, ipv4_str, &(node_info->hdr.ext_addr_v4));
        if(ipv6_str)
            inet_pton(AF_INET6, ipv6_str, &(node_info->hdr.ext_addr_v6));
    }
    if(alias_str) {
        if(addr_str) {
            // add alias
            if(!add_alias(alias_str, &node_info->hdr.address))
                log_it(L_WARNING, "can't save alias %s", alias_str);
        }
        else {
            if(str_reply)
                *str_reply = g_strdup("alias can't be mapped because -addr is not found");
            return -1;
        }
    }
    // check match addr to shard or no
    /*dap_chain_node_addr_t *addr = dap_chain_node_gen_addr(&node_info->hdr.shard_id);
     if(!dap_chain_node_check_addr(&node_info->hdr.address, &node_info->hdr.shard_id)) {
     if(str_reply)
     *str_reply = g_strdup("shard does not match addr");
     return -1;
     }*/

    // write to base
    char *a_key = dap_chain_global_db_hash((const uint8_t*) &(node_info->hdr.address),
            sizeof(dap_chain_node_addr_t));
    char *a_value = dap_chain_node_serialize(node_info, NULL);
    bool res = dap_chain_global_db_gr_set(a_key, a_value, GROUP_NODE);
    if(res) {
        if(str_reply)
            *str_reply = g_strdup_printf("node is added");
    }
    else if(str_reply) {
        *str_reply = g_strdup_printf("node is not added");
    }
    DAP_DELETE(a_key);
    DAP_DELETE(a_value);
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
static int com_global_db_del(dap_chain_node_info_t *node_info, const char *addr_str,
        const char *alias_str, char **str_reply)
{
    char *a_key = NULL;
    // find addr by alias
    dap_chain_node_addr_t *address = NULL;
    if(alias_str && !addr_str) {
        address = get_name_by_alias(alias_str);
        if(!address) {
            *str_reply = g_strdup("alias not found");
            return -1;
        }
        a_key = dap_chain_global_db_hash((const uint8_t*) address, sizeof(dap_chain_node_addr_t));
    }
    if(addr_str)
    {
        a_key = dap_chain_global_db_hash((const uint8_t*) &(node_info->hdr.address), sizeof(dap_chain_node_addr_t));
        if(a_key) {
            address = DAP_NEW(dap_chain_node_addr_t);
            address->uint64 = node_info->hdr.address.uint64;
        }
    }
    if(a_key)
    {
        // delete node
        bool res = dap_chain_global_db_gr_del(a_key, GROUP_NODE);
        if(res) {
            // delete all aliases for node address
            {
                char *alias = NULL;
                do {
                    alias = get_alias_by_name(address);
                    del_alias(alias);
                }
                while(alias);
            }
            if(str_reply)
                *str_reply = g_strdup_printf("node is deleted");
        }
        else if(str_reply) {
            *str_reply = g_strdup_printf("node is not deleted");
        }
        DAP_DELETE(a_key);
        if(res)
            return 0;
    }
    if(str_reply)
        *str_reply = g_strdup("addr to delete can't be defined");
    DAP_DELETE(address);
    return -1;
}

/**
 * Handler of command 'global_db node link'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_link(dap_chain_node_info_t *node_info, const char *addr_str,
        const char *alias_str, char **str_reply)
{
    char *a_key = NULL;
    // find addr by alias
    dap_chain_node_addr_t *address = NULL;
    if(alias_str && !addr_str) {
        address = get_name_by_alias(alias_str);
        if(!address) {
            *str_reply = g_strdup("alias not found");
            return -1;
        }
        a_key = dap_chain_global_db_hash((const uint8_t*) address, sizeof(dap_chain_node_addr_t));
    }
    if(addr_str)
    {
        a_key = dap_chain_global_db_hash((const uint8_t*) &(node_info->hdr.address), sizeof(dap_chain_node_addr_t));
        if(a_key) {
            address = DAP_NEW(dap_chain_node_addr_t);
            address->uint64 = node_info->hdr.address.uint64;
        }
    }
    if(a_key)
    {
        // add link
        bool res = 0; //dap_chain_global_db_gr_read(a_key, GROUP_NODE);
        if(res) {

        }
        DAP_DELETE(a_key);
        if(res)
            return 0;
    }
    if(str_reply)
        *str_reply = g_strdup("link addr can't be saved");
    DAP_DELETE(address);
    return -1;
}

/**
 * Handler of command 'global_db node dump'
 *
 * str_reply[out] for reply
 * return 0 Ok, -1 error
 */
static int com_global_db_dump(dap_chain_node_info_t *node_info, const char *addr_str,
        const char *alias_str, char **str_reply)
{
    char *a_key = NULL;
    if(!addr_str && !alias_str) {
        *str_reply = g_strdup("addr not found");
        return -1;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *address = com_global_db_get_addr(node_info, addr_str, alias_str);
    if(!address) {
        *str_reply = g_strdup("alias not found");
        return -1;
    }
    a_key = com_global_db_get_key_for_addr(address);
    if(a_key)
    {
        // read node
        char *str = dap_chain_global_db_gr_get(a_key, GROUP_NODE);
        if(str) {
            dap_chain_node_info_t *node_info = dap_chain_node_deserialize(str, strlen(str));
            if(str_reply)
            {
                // TODO dump insert here!
                *str_reply = g_strdup_printf("node is read");
            }
        }
        else if(str_reply) {
            *str_reply = g_strdup_printf("node is not found in base");
        }
        DAP_DELETE(str);
        DAP_DELETE(a_key);
        DAP_DELETE(address);
        if(str)
            return 0;
        return -1;
    }
    if(str_reply)
        *str_reply = g_strdup("addr to dump can't be defined");
    DAP_DELETE(address);
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
    // find 'node' parameter
    arg_index = find_option_val(argv, arg_index, argc, "node", NULL);
    if(!arg_index || argc < 4) {
        if(str_reply)
            *str_reply = g_strdup("parameters are not valid");
        return -1;
    }
    arg_index++;
    // find command (add, delete, etc)
    int cmd_num = CMD_NONE;
    if(find_option_val(argv, arg_index, argc, "add", NULL)) {
        cmd_num = CMD_ADD;
    }
    else if(find_option_val(argv, arg_index, argc, "del", NULL)) {
        cmd_num = CMD_DEL;
    }
    else if(find_option_val(argv, arg_index, argc, "link", NULL)) {
        cmd_num = CMD_LINK;
    }
    else if(find_option_val(argv, arg_index, argc, "dump", NULL)) {
        cmd_num = CMD_DUMP;
    }
    if(cmd_num == CMD_NONE) {
        if(str_reply)
            *str_reply = g_strdup_printf("command %s not recognized", argv[1]);
        return -1;
    }
    const char *addr_str = NULL, *alias_str = NULL, *shard_str = NULL, *ipv4_str = NULL, *ipv6_str = NULL;
    // find addr, alias
    find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    find_option_val(argv, arg_index, argc, "-alias", &alias_str);
    find_option_val(argv, arg_index, argc, "-shard", &shard_str);
    find_option_val(argv, arg_index, argc, "-ipv4", &ipv4_str);
    find_option_val(argv, arg_index, argc, "-ipv6", &ipv6_str);

    // struct to write to the global db
    dap_chain_node_info_t node_info;
    memset(&node_info, 0, sizeof(dap_chain_node_info_t));
    if(addr_str) {
        digit_from_string(addr_str, node_info.hdr.address.raw, sizeof(node_info.hdr.address.raw));
    }
    if(shard_str) {
        digit_from_string(shard_str, node_info.hdr.shard_id.raw, sizeof(node_info.hdr.shard_id.raw)); //DAP_CHAIN_SHARD_ID_SIZE);
    }

    switch (cmd_num)
    {
    // add new node to global_db
    case CMD_ADD:
        if(!arg_index || argc < 8) {
            if(str_reply)
                *str_reply = g_strdup("parameters are not valid");
            return -1;
        }
        // handler of command 'global_db node add'
        return com_global_db_add(&node_info, addr_str, alias_str, shard_str, ipv4_str, ipv6_str, str_reply);
        break;

    case CMD_DEL:
        // handler of command 'global_db node del'
        return com_global_db_del(&node_info, addr_str, alias_str, str_reply);
        break;
    case CMD_LINK:
        // handler of command 'global_db node link'
        return com_global_db_link(&node_info, addr_str, alias_str, str_reply);
        break;
    case CMD_DUMP:
        // handler of command 'global_db node dump'
        return com_global_db_dump(&node_info, addr_str, alias_str, str_reply);
        break;
    default:
        if(str_reply)
            *str_reply = g_strdup_printf("command %s not recognized", argv[1]);
        return -1;
    }

//inet_ntop(AF_INET, &(dap_addr.uint64), str, INET_ADDRSTRLEN);
//uint64
//    timestamp = time(NULL);

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
        if(str_reply)
            *str_reply = g_strdup_printf("command %s not recognized", argv[1]);
        return -1;
    }
    dap_chain_node_addr_t address;
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
                    if(str_reply)
                        *str_reply = g_strdup("alias mapped successfully");
                }
            }
            else {
                if(str_reply)
                    *str_reply = g_strdup("alias can't be mapped because -addr is not found");
                return -1;
            }
        }
        else {
            if(str_reply)
                *str_reply = g_strdup("alias can't be mapped because -alias is not found");
            return -1;
        }

        break;

        // make handshake
    case CMD_HANDSHAKE:
        if(str_reply)
            *str_reply = g_strdup("handshake in progress...");
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
        if(str_reply)
            *str_reply = g_strdup_printf("traceroute %s hops=%d time=%.1lf ms", addr, hops, time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                *str_reply = g_strdup_printf("traceroute %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case 2:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "Unknown traceroute module");
                break;
            case 3:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "first hop out of range");
                break;
            case 4:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "max hops cannot be more than 255");
                break;
            case 5:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "no more than 10 probes per hop");
                break;
            case 6:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "bad wait specifications");
                break;
            case 7:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "too big packetlen ");
                break;
            case 8:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr,
                        "IP version mismatch in addresses specified");
                break;
            case 9:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "bad sendtime");
                break;
            case 10:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "init_ip_options");
                break;
            case 11:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "calloc");
                break;
            case 12:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "parse cmdline");
                break;
            case 13:
                *str_reply = g_strdup_printf("traceroute %s error: %s", addr, "trace method's init failed");
                break;
            default:
                *str_reply = g_strdup_printf("traceroute %s error(%d) %s", addr, res, "trace not found");
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
            *str_reply = g_strdup_printf("tracepath %s hops=%d time=%.1lf ms", addr, hops, time_usec * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EADDRNOTAVAIL:
                *str_reply = g_strdup_printf("tracepath %s error: %s", (addr) ? addr : "",
                        (addr) ? "Name or service not known" : "Host not defined");
                break;
            case ESOCKTNOSUPPORT:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't create socket");
                break;
            case 2:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_MTU_DISCOVER");
                break;
            case 3:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_RECVERR");
                break;
            case 4:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_HOPLIMIT");
                break;
            case 5:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_MTU_DISCOVER");
                break;
            case 6:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_RECVERR");
                break;
            case 7:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_RECVTTL");
                break;
            case 8:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "malloc");
                break;
            case 9:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IPV6_UNICAST_HOPS");
                break;
            case 10:
                *str_reply = g_strdup_printf("tracepath %s error: %s", addr, "Can't setsockopt IP_TTL");
                break;
            default:
                *str_reply = g_strdup_printf("tracepath %s error(%d) %s", addr, res, "trace not found");
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
            *str_reply = g_strdup_printf("ping %s time=%.1lf ms", addr, res * 1. / 1000);
    }
    else {
        if(str_reply) {
            switch (-res)
            {
            case EDESTADDRREQ:
                *str_reply = g_strdup_printf("ping %s error: %s", addr, "Destination address required");
                break;
            case EADDRNOTAVAIL:
                *str_reply = g_strdup_printf("ping %s error: %s", (addr) ? addr : "",
                        (addr) ? "Host not found" : "Host not defined");
                break;
            case EPFNOSUPPORT:
                *str_reply = g_strdup_printf("ping %s error: %s", addr, "Unknown protocol family");
                break;
            default:
                *str_reply = g_strdup_printf("ping %s error(%d)", addr, -res);
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
            if(str_reply)
                *str_reply = g_strdup(cmd->doc);
            return 1;
        }
        if(str_reply)
            *str_reply = g_strdup_printf("command \"%s\" not recognized", argv[1]);
    }
    if(str_reply)
        *str_reply = g_strdup("command not defined, enter \"help <cmd name>\"");
    return -1;
}


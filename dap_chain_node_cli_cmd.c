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

uint8_t* dap_chain_global_db_node_serialize(dap_chain_node_info_t *node_info, size_t *size)
{
    if(!node_info)
        return NULL;
    size_t node_info_size = sizeof(dap_chain_node_info_t) + node_info->hdr.uplinks_number * sizeof(dap_chain_addr_t);
    size_t a_request_size = 2 * node_info_size + 1;
    uint8_t *a_request = DAP_NEW_Z_SIZE(uint8_t, a_request_size);

    bin2hex(a_request, (const unsigned char *)node_info, node_info_size);
    if(size)
        *size = a_request_size;
    return a_request;
}

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
 * global_db command
 *
 * return 0 OK, -1 Err
 */
int com_global_db(int argc, const char ** argv, char **str_reply)
{
    printf("com_global_db\n");
    int arg_index = 1;
    const char *cmd_str = NULL;
    // find 'node' parameter
    arg_index = find_option_val(argv, arg_index, argc, "node", NULL);
    if(!arg_index || argc < 5) {
        if(str_reply)
            *str_reply = g_strdup("parameters are not valid");
        return -1;
    }
    arg_index++;
    // find command (add or del)
    int cmd_num = 0;
    if(find_option_val(argv, arg_index, argc, "add", NULL)) {
        cmd_num = 1;
    }
    else if(find_option_val(argv, arg_index, argc, "del", NULL)) {
        cmd_num = 2;
    }
    if(!cmd_num) {
        if(str_reply)
            *str_reply = g_strdup_printf("command %s not recognized", argv[1]);
        return -1;
    }
    const char *addr_str = NULL, *shard_str = NULL, *ipv4_str = NULL, *ipv6_str = NULL;
    // find addr & alias
    find_option_val(argv, arg_index, argc, "-addr", &addr_str);
    find_option_val(argv, arg_index, argc, "-shard", &shard_str);
    find_option_val(argv, arg_index, argc, "-ipv4", &ipv4_str);
    find_option_val(argv, arg_index, argc, "-ipv6", &ipv6_str);
    if(!arg_index || argc < 5) {
        if(str_reply)
            *str_reply = g_strdup("parameters are not valid");
        return -1;
    }
    if(!addr_str) {
        if(str_reply)
            *str_reply = g_strdup("not found -addr parameter");
        return -1;
    }
    dap_chain_node_info_t node_info;
    memset(&node_info, 0, sizeof(dap_chain_node_info_t));

    // store this IP address in dap_addr, dap_addr.uint64 = struct sockaddr_in.sin_addr
    inet_pton(AF_INET, addr_str, &(node_info.hdr.address.uint64));
    memcpy(&(node_info.hdr.address.raw), &(node_info.hdr.address.uint64), sizeof(uint64_t));
    // now get it back
    //inet_ntop(AF_INET, &(node_info.hdr.address.uint64), str, INET6_ADDRSTRLEN);

    if(shard_str) {
        int64_t shard_id = strtoll(shard_str, NULL, 10);
        memcpy(&node_info.hdr.shard_id.raw, &shard_id, sizeof(int64_t));
    }

    //inet_ntop(AF_INET, &(dap_addr.uint64), str, INET_ADDRSTRLEN);
    //uint64
    uint64_t
    timestamp = time(NULL);

    char *a_key = dap_chain_global_db_hash((const uint8_t*)&(node_info.hdr.address), sizeof(dap_chain_node_addr_t));
    char *a_value = dap_chain_global_db_node_serialize(&node_info, NULL);
    bool res = dap_chain_global_db_set(a_key, a_value);
    if(res) {
        if(str_reply)
            *str_reply = g_strdup_printf("node is %s", (cmd_num == 1) ? "added" : "deleted");
        return 0;
    }
    else if(str_reply) {
        *str_reply = g_strdup_printf("node is not %s", (cmd_num == 1) ? "added" : "deleted");
    }
    DAP_DELETE(a_value);
    return -1;
}

/**
 * Node command
 */
int com_node(int argc, const char ** argv, char **str_reply)
{
    for(int i = 0; i < argc; i++)
        printf("com_node i=%d str=%s\n", i, argv[i]);
    if(str_reply)
        *str_reply = g_strdup("text");
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


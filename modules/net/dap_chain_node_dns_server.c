/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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

#include <errno.h>
#include "dap_chain_node_dns_client.h"
#include "dap_chain_node_dns_server.h"
#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_common.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"
#include "dap_string.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#define LOG_TAG "dap_chain_node_dns_server"
#define BUF_SIZE 1024

static dap_dns_server_t *s_dns_server;
static char s_root_alias[] = "dnsroot";


/**
 * @brief dap_dns_zone_register Register DNS zone and set callback to handle it
 * @param zone Name of zone to register
 * @param callback Callback to handle DNS zone
 * @return 0 if success, else return error code
 */
int dap_dns_zone_register(char *zone, dap_dns_zone_callback_t callback) {
    dap_dns_zone_hash_t *new_zone;
    HASH_FIND_STR(s_dns_server->hash_table, zone, new_zone);
    if (new_zone == NULL) {      // zone is not present
      new_zone = DAP_NEW(dap_dns_zone_hash_t);
      new_zone->zone = dap_strdup(zone);
      HASH_ADD_KEYPTR(hh, s_dns_server->hash_table, new_zone->zone, strlen(new_zone->zone), new_zone);
    }                           // if zone present, just reassign callback
    new_zone->callback = callback;
    return DNS_ERROR_NONE;
}

/**
 * @brief dap_dns_zone_unregister Unregister DNS zone
 * @param zone Name of zone to unregister
 * @return 0 if success, else return error code
 */
int dap_dns_zone_unregister(char *zone) {
    dap_dns_zone_hash_t *asked_zone;
    HASH_FIND_STR(s_dns_server->hash_table, zone, asked_zone);
    if (asked_zone == NULL) {
        return DNS_ERROR_NAME;
    }
    HASH_DEL(s_dns_server->hash_table, asked_zone);
    DAP_DELETE(asked_zone->zone);
    DAP_DELETE(asked_zone);
    return DNS_ERROR_NONE;
}

/**
 * @brief dap_dns_zone_find Find callback to registered DNS zone
 * @param hostname Name of host for which the zone callback being searched
 * @return Callback for registered DNS zone, else return NULL
 */
dap_dns_zone_callback_t dap_dns_zone_find(char *hostname) {
    dap_dns_zone_hash_t *asked_zone;
    HASH_FIND_STR(s_dns_server->hash_table, hostname, asked_zone);
    if (asked_zone == NULL) {
        if (!strcmp(hostname, &s_root_alias[0])) {
            return NULL;
        }
        char *zone_up = strchr(hostname, '.');
        if (zone_up++ == NULL) {
            zone_up = &s_root_alias[0];
        }
        return dap_dns_zone_find(zone_up);
    } else {
        return asked_zone->callback;
    }
    return NULL;
}

/**
 * @brief dap_dns_client_read Read and parse incoming DNS message, send reply to it
 * @param client DAP client remote structure
 * @param arg Unused
 * @return none
 */
void dap_dns_client_read(dap_events_socket_t *a_es, void *a_arg) {
    UNUSED(a_arg);
    if (a_es->buf_in_size < DNS_HEADER_SIZE) {        // Bad request
        return;
    }
    dap_dns_buf_t *dns_message = DAP_NEW(dap_dns_buf_t);
    dap_dns_buf_t *dns_reply = DAP_NEW(dap_dns_buf_t);
    dns_message->data = DAP_NEW_SIZE(char, a_es->buf_in_size + 1);
    dns_message->data[a_es->buf_in_size] = 0;
    dap_events_socket_pop_from_buf_in(a_es, dns_message->data, a_es->buf_in_size);
    dns_message->size = 0;

    // Parse incoming DNS message
    int block_len = DNS_HEADER_SIZE;
    dns_reply->data = DAP_NEW_SIZE(char, block_len);
    dns_reply->size = 0;
    uint16_t val = dap_dns_buf_get_uint16(dns_message); // ID
    dap_dns_buf_put_uint16(dns_reply, val);
    val = dap_dns_buf_get_uint16(dns_message);          // Flags
    dns_reply->size += sizeof(uint16_t);                 // Put flags later
    dap_dns_message_flags_t msg_flags;
    msg_flags.val = val;
    dap_dns_message_flags_bits_t *flags = &msg_flags.flags;
    if (flags->qr) {                                     // It's not request
        goto cleanup;
    }
    flags->rcode = DNS_ERROR_NONE;
    flags->qr = 1;                                       // Response bit set
    if (flags->tc) {                                     // Truncated messages not supported yet
        flags->rcode = DNS_ERROR_NOT_SUPPORTED;
    }
    flags->ra = 0;                                       // Recursion not supported yet
    flags->aa = 1;                                       // Authoritative answer
    uint16_t qdcount = dap_dns_buf_get_uint16(dns_message);
    dap_dns_buf_put_uint16(dns_reply, qdcount);
    val = dap_dns_buf_get_uint16(dns_message);          // AN count
    if (val) {                                          // No other sections should present
        goto cleanup;
    }
    dap_dns_buf_put_uint16(dns_reply, 1);               // 1 answer section
    val = dap_dns_buf_get_uint16(dns_message);          // NS count
    if (val) {                                          // No other sections should present
        goto cleanup;
    }
    dap_dns_buf_put_uint16(dns_reply, val);
    val = dap_dns_buf_get_uint16(dns_message);          // AR count
    if (val) {                                          // No other sections should present
        goto cleanup;
    }
    dap_dns_buf_put_uint16(dns_reply, 1);               // 1 aditional section
    int dot_count = 0;
    dap_string_t *dns_hostname = dap_string_new("");
    for (int i = 0; i < qdcount; i++) {
        block_len = strlen(&dns_message->data[dns_message->size]) + 1 + 2 * sizeof(uint16_t);
        dns_reply->data = DAP_REALLOC(dns_reply->data, dns_reply->size + block_len);
        memcpy(&dns_reply->data[dns_reply->size], &dns_message->data[dns_message->size], block_len);
        dns_reply->size += block_len;
        if (flags->rcode)
            break;
        while (dns_message->size < dns_reply->size - 2 * sizeof(uint16_t)) {
            uint8_t len = dns_message->data[dns_message->size++];
            if (len > DNS_MAX_DOMAIN_NAME_LEN) {
                flags->rcode = DNS_ERROR_NAME;
                break;
            }
            if (!len) {
                break;
            }
            if (dot_count) {
                if (dot_count > 3) {                    // Max three dots allowed
                    flags->rcode = DNS_ERROR_NAME;
                    break;
                }
                dap_string_append(dns_hostname, ".");
            }
            dap_string_append_len(dns_hostname, &dns_message->data[dns_message->size], len);
            dns_message->size += len;
            dot_count++;
            if (dns_hostname->len >= DNS_MAX_HOSTNAME_LEN) {
                flags->rcode = DNS_ERROR_NAME;
                break;
            }
        }
        val = dap_dns_buf_get_uint16(dns_message);      // DNS record type
        if (val != DNS_RECORD_TYPE_A) {                 // Only host address ipv4
            flags->rcode = DNS_ERROR_NOT_SUPPORTED;
            break;
        }
        val = dap_dns_buf_get_uint16(dns_message);      // DNS class type
        if (val != DNS_CLASS_TYPE_IN) {                 // Internet only
            flags->rcode = DNS_ERROR_NOT_SUPPORTED;
            break;
        }
        if (dns_message->size != dns_reply->size) {
            log_it(L_ERROR, "DNS parser pointer unequal, mptr = %u, rptr = %u", dns_message->size, dns_reply->size);
        }
    }
    // Find ip addr
    dap_chain_node_info_t *l_node_info = NULL;
    if (flags->rcode == DNS_ERROR_NONE) {
        dap_dns_zone_callback_t callback = dap_dns_zone_find(dns_hostname->str);
        if (callback) {
            l_node_info = callback(dns_hostname->str);
        }
    }
    if (l_node_info) {
        // Compose DNS answer
        block_len = DNS_ANSWER_SIZE * 2 - sizeof(uint16_t) + sizeof(uint64_t);
        dns_reply->data = DAP_REALLOC(dns_reply->data, dns_reply->size + block_len);
        val = 0xc000 | DNS_HEADER_SIZE;                // Link to host name
        dap_dns_buf_put_uint16(dns_reply, val);
        val = DNS_RECORD_TYPE_A;
        dap_dns_buf_put_uint16(dns_reply, val);
        val = DNS_CLASS_TYPE_IN;
        dap_dns_buf_put_uint16(dns_reply, val);
        uint32_t ttl = DNS_TIME_TO_LIVE;
        dap_dns_buf_put_uint32(dns_reply, ttl);                                    
        dap_dns_buf_put_uint16(dns_reply, 4);           // RD len for ipv4
        dap_dns_buf_put_uint32(dns_reply, l_node_info->hdr.ext_addr_v4.s_addr);
        val = 0xc000 | DNS_HEADER_SIZE;                // Link to host name
        dap_dns_buf_put_uint16(dns_reply, val);
        val = DNS_RECORD_TYPE_TXT;
        dap_dns_buf_put_uint16(dns_reply, val);
        val = DNS_CLASS_TYPE_IN;
        dap_dns_buf_put_uint16(dns_reply, val);
        dap_dns_buf_put_uint32(dns_reply, ttl);
        val = sizeof(uint16_t) + sizeof(uint64_t);
        dap_dns_buf_put_uint16(dns_reply, val);
        dap_dns_buf_put_uint16(dns_reply, l_node_info->hdr.ext_port);
        dap_dns_buf_put_uint64(dns_reply, l_node_info->hdr.address.uint64);
        DAP_DELETE(l_node_info);
    } else if (flags->rcode == DNS_ERROR_NONE) {
        flags->rcode = DNS_ERROR_NAME;
    }
    if (flags->rcode) {
        dns_reply->data[7] = 0;                         // No answer section
    }
    // Set reply flags
    dns_reply->data[2] = msg_flags.val >> 8;
    dns_reply->data[3] = msg_flags.val;
    // Send DNS reply
    dap_events_socket_write_unsafe(a_es, dns_reply->data, dns_reply->size);
    dap_string_free(dns_hostname, true);
cleanup:
    DAP_DELETE(dns_reply->data);
    DAP_DELETE(dns_message->data);
    DAP_DELETE(dns_reply);
    DAP_DELETE(dns_message);
    return;
}

void dap_dns_server_start(dap_events_t *a_ev, uint16_t a_port)
{
    s_dns_server = DAP_NEW_Z(dap_dns_server_t);
    dap_events_socket_callbacks_t l_cb = {};
    l_cb.read_callback = dap_dns_client_read;
    s_dns_server->instance = dap_server_new(a_ev, NULL, a_port, SERVER_UDP, &l_cb);
    if (!s_dns_server->instance) {
        log_it(L_ERROR, "Can't start DNS server");
        return;
    }
    dap_dns_zone_register(&s_root_alias[0], dap_dns_resolve_hostname);  // root resolver
    log_it(L_NOTICE,"DNS server started");
}

void dap_dns_server_stop() {
    if(!s_dns_server)
        return;

    dap_dns_zone_hash_t *current_zone, *tmp;
    HASH_ITER(hh, s_dns_server->hash_table, current_zone, tmp) {
        HASH_DEL(s_dns_server->hash_table, current_zone);
        DAP_DELETE(current_zone->zone);
        DAP_DELETE(current_zone);
    }
    dap_server_delete(s_dns_server->instance);
    DAP_DELETE(s_dns_server);
}

/**
 * @brief dap_dns_resolve_hostname
 * @param str
 * @return
 */
dap_chain_node_info_t *dap_dns_resolve_hostname(char *str)
{
    log_it(L_DEBUG, "DNS parser retrieve hostname %s", str);
    dap_chain_net_t *l_net = dap_chain_net_by_name(str);
    if (l_net == NULL) {
        uint16_t l_nets_count;
        dap_chain_net_t **l_nets = dap_chain_net_list(&l_nets_count);
        if (!l_nets_count) {
            log_it(L_WARNING, "No chain network present");
            return NULL;
        }
        l_net = l_nets[rand() % l_nets_count];
    }
    // get nodes list from global_db
    dap_global_db_obj_t *l_objs = NULL;
    size_t l_nodes_count = 0;
    // read all node
    l_objs = dap_chain_global_db_gr_load(l_net->pub.gdb_nodes, &l_nodes_count);
    if (!l_nodes_count || !l_objs)
        return NULL;
    dap_chain_node_info_t *l_node_candidate;
    for (int i = 0; i < 50; i++) {
        // 50 tryes for non empty address & port
        size_t l_node_num = rand() % l_nodes_count;
        l_node_candidate = (dap_chain_node_info_t *)l_objs[l_node_num].value;
        if (l_node_candidate->hdr.ext_addr_v4.s_addr && l_node_candidate->hdr.ext_port)
            break;
    }
    if (!l_node_candidate->hdr.ext_addr_v4.s_addr || !l_node_candidate->hdr.ext_port)
        return NULL;
    dap_chain_node_info_t *l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    memcpy(l_node_info, l_node_candidate, sizeof(dap_chain_node_info_t));
    dap_chain_global_db_objs_delete(l_objs, l_nodes_count);
    log_it(L_DEBUG, "DNS resolver find ip %s", inet_ntoa(l_node_info->hdr.ext_addr_v4));
    return l_node_info;
}

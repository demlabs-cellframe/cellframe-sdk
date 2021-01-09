/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * Dmitriy Gerasimov <dmitriy.gerasmiov@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DapChain SDK the open source project

    DapChain SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DapChain SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DapChain SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#ifdef _WIN32
#include <pthread.h>
#endif
#include "dap_server.h"
#include "dap_chain_node.h"
#include "uthash.h"

#define DNS_TIME_TO_LIVE 600    // Seconds
#define DNS_HEADER_SIZE 12
#define DNS_ANSWER_SIZE 16
#define DNS_MAX_HOSTNAME_LEN 255
#define DNS_MAX_DOMAIN_NAME_LEN 63

typedef enum _dap_dns_query_type_t {
    DNS_QUERY_TYPE_STANDARD,
    DNS_QUERY_TYPE_INVERSE,
    DNS_QUERY_TYPE_STATUS
} dap_dns_query_type_t;

typedef enum _dap_dns_error_t {
    DNS_ERROR_NONE,         // No error
    DNS_ERROR_FORMAT,       // DNS message parsing error
    DNS_ERROR_FAILURE,      // Internal server error
    DNS_ERROR_NAME,         // Only for authoritative servers. Name does not exist
    DNS_ERROR_NOT_SUPPORTED,// This kind of query not implemented
    DNS_ERROR_REFUSED       // Operation refused
} dap_dns_error_t;

typedef enum _dap_dns_record_type_t {
    DNS_RECORD_TYPE_A = 1,  // Host address
    DNS_RECORD_TYPE_NS,     // Authoritative name server
    DNS_RECORD_TYPE_MD,     // Mail destination (obsolete, use MX)
    DNS_RECORD_TYPE_MF,     // Mail forwarder (obsolete, use MX)
    DNS_RECORD_TYPE_CNAME,  // Canonical name of alias
    DNS_RECORD_TYPE_SOA,    // Marks a start of a zone of authority
    DNS_RECORD_TYPE_MB,     // Mailbox domain name (experimental)
    DNS_RECORD_TYPE_MG,     // Mail group member (experimental)
    DNS_RECORD_TYPE_MR,     // Mail rename domain name (experimental)
    DNS_RECORD_TYPE_NULL,   // NULL resource record (experimental)
    DNS_RECORD_TYPE_WKS,    // Well known services description
    DNS_RECORD_TYPE_PTR,    // Domain name pointer
    DNS_RECORD_TYPE_HINFO,  // Host information
    DNS_RECORD_TYPE_MINFO,  // Mail box or list information
    DNS_RECORD_TYPE_MX,     // Mail exchange
    DNS_RECORD_TYPE_TXT,    // Text strings
    DNS_RECORD_TYPE_RP,     // Responsible person
    DNS_RECORD_TYPE_AXFR = 252, // A request for a transfer of an entire zone - QTYPE only
    DNS_RECORD_TYPE_MAILB,  // A request for mailbox-related records (MB, MG or MR) - QTYPE only
    DNS_RECORD_TYPE_MAILA,  // A request for mail agent RRs (obsolete - see MX) - QTYPE only
    DNS_RECORD_TYPE_ANY     // A request for all records - QTYPE only
} dap_dns_record_type_t;

typedef enum _dap_dns_class_type_t {
    DNS_CLASS_TYPE_IN = 1,  // Internet
    DNS_CLASS_TYPE_CS,      // CSNET (obsolete)
    DNS_CLASS_TYPE_CH,      // CHAOS
    DNS_CLASS_TYPE_HS,      // Hesiod [Dyer 87]
    DNS_CLASS_TYPE_ANY = 255    // Any class
} dap_dns_class_type_t;

typedef struct _dap_dns_message_flags_bits_t {
    int rcode : 4;          // response code, answer only: 0 - no error, 1 - format error, 2 - server failure, 3 - name error, 4 - not supported, 5 - refused
    int z : 3;              // reserved, must be zero
    int ra : 1;             // 1 - recursion available (answer only)
    int rd : 1;             // 1 - recursion desired (query set, copied to answer)
    int tc : 1;             // 1 - message truncated
    int aa : 1;             // 1 - authoritative answer (answer only)
    int opcode : 4;         // type of query, copied to answer: 0 - standard, 1 - inverse, 2 - status, 3-15 - reserved
    int qr : 1;             // 0 - query, 1 - response
} dap_dns_message_flags_bits_t;


typedef union _dap_dns_message_flags_t {
    dap_dns_message_flags_bits_t flags;
    int val;
} dap_dns_message_flags_t;

typedef dap_chain_node_info_t *(*dap_dns_zone_callback_t) (char *hostname); // Callback for DNS zone operations

typedef struct _dap_dns_zone_hash_t {
    char *zone;
    dap_dns_zone_callback_t callback;
    UT_hash_handle hh;
} dap_dns_zone_hash_t;

typedef struct _dap_dns_server_t {
    dap_server_t *instance;
    dap_dns_zone_hash_t *hash_table;
} dap_dns_server_t;



void dap_dns_server_start(dap_events_t *a_ev, uint16_t a_port);
void dap_dns_server_stop();
int dap_dns_zone_register(char *zone, dap_dns_zone_callback_t callback);
int dap_dns_zone_unregister(char *zone);


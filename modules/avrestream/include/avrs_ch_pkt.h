/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of AVReStream

 AVReStream is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 AVReStream is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any AVReStream based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include <dap_common.h>
#include <stdint.h>
#include <dap_stream_ch.h>
#include "avrs.h"
#include "dap_events_socket.h"

#define AVRS_CH_PKT_CLUSTER_TYPE_CREATE                   0x01
#define AVRS_CH_PKT_CLUSTER_TYPE_DESTROY                  0x02
#define AVRS_CH_PKT_CLUSTER_TYPE_CHANGE                   0x03
#define AVRS_CH_PKT_CLUSTER_TYPE_INFO                     0x04
#define AVRS_CH_PKT_CLUSTER_TYPE_LIST_REQUEST             0x05
#define AVRS_CH_PKT_CLUSTER_TYPE_LIST_RESPONSE            0x06

#define AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REQUEST_ADD       0x10
#define AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REQUEST_DEL       0x11
#define AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REQUEST_APPROVE   0x12
#define AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REMOVE            0x13
#define AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_ROLE_ASSIGN       0x14

#define AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_ADD              0x20
#define AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_UPDATE           0x21
#define AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_DEL              0x22
#define AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_LIST_REQUEST     0x23
#define AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_LIST_RESPONSE    0x24

#define AVRS_CH_PKT_CLUSTER_TYPE_BALANCE_REQUEST          0x30
#define AVRS_CH_PKT_CLUSTER_TYPE_BALANCE_RESPONSE         0x31

#define AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_ADD                0x40
#define AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_DEL                0x41
#define AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_FIND               0x42
#define AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_CHECK              0x43

#define AVRS_CH_PKT_CLUSTER_ARG_ID                        0x0001
#define AVRS_CH_PKT_CLUSTER_ARG_TITLE                     0x0002
#define AVRS_CH_PKT_CLUSTER_ARG_SETUP                     0x0003
#define AVRS_CH_PKT_CLUSTER_ARG_ENCRYPTED                 0x0004

#define AVRS_CH_PKT_CLUSTER_ARG_MEMBERS_COUNT             0x0010
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBERS_COUNT_MAX         0x0011

// Member argument types
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER                    0x0013
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ROLE               0x0014
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ADDR               0x0015
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_DISPLAY_NAME       0x0016
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_NAME               0x0017
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SECOND_NAME        0x0018
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SURNAME            0x0019
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_PATRONIM           0x001A
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_AVATAR             0x001B
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_STATUS             0x001C
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_TITLE              0x001D
#define AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SIGNAL             0x001E

// Content argument types
#define AVRS_CH_PKT_CLUSTER_ARG_CONTENT_ID                0x0030
#define AVRS_CH_PKT_CLUSTER_ARG_CONTENT_TITEL             0x0031
#define AVRS_CH_PKT_CLUSTER_ARG_CONTENT_FLOWS             0x0033
#define AVRS_CH_PKT_CLUSTER_ARG_CONTENT_FLOW_CODEC        0x0034
// Flow TSD section
typedef struct avrs_ch_pkt_tsd_flow
{
    uint8_t id; // Flow number
    byte_t data[];
} DAP_ALIGN_PACKED avrs_ch_pkt_tsd_flow_t;

// Cluster packet signature, have to be in the end of arg list
// and signs everythign before the packet
#define AVRS_CH_PKT_CLUSTER_ARG_SIGN                        0xffff


// Cluster control packet
typedef struct avrs_ch_pkt_cluster{

    uint8_t     type;                                                   /* Operation code or packet type, see : AVRS_CH_PKT_CLUSTER_TYPE* constants */
    uint8_t     padding[7];
    uint8_t     args[];                                                 /* Operation args in TSD format, see AVRS_CH_PKT_CLUSTER_ARG* constant */
} DAP_ALIGN_PACKED avrs_ch_pkt_cluster_t;

#define AVRS_CH_PKT_SESSION_TYPE_OPEN                0x01
#define AVRS_CH_PKT_SESSION_TYPE_UPDATE              0x02
#define AVRS_CH_PKT_SESSION_TYPE_CLOSE               0x03

#define AVRS_CH_PKT_SESSION_TYPE_CONTENT_ADD         0x10
#define AVRS_CH_PKT_SESSION_TYPE_CONTENT_REMOVE      0x11
#define AVRS_CH_PKT_SESSION_TYPE_CONTENT_UPDATE      0x12

#define AVRS_CH_PKT_SESSION_TYPE_CLUSTER_ADD         0x20
#define AVRS_CH_PKT_SESSION_TYPE_CLUSTER_DEL         0x21
#define AVRS_CH_PKT_SESSION_TYPE_CLUSTER_UPDATE      0x22

// Session packet signature, have to be in the end of arg list
// and signs everythign before the packet
#define AVRS_CH_PKT_SESSION_ARG_SIGN                 0x0001
#define AVRS_CH_PKT_SESSION_ARG_CLUSTER_UUID         0x0010
#define AVRS_CH_PKT_SESSION_ARG_CLUSTER_ID           0x0011
#define AVRS_CH_PKT_SESSION_ARG_CONTENT_UUID         0x0020
#define AVRS_CH_PKT_SESSION_ARG_CONTENT_ID           0x0021
#define AVRS_CH_PKT_SESSION_ARG_CONTENT_FLAGS        0x0022

// Session control packet
typedef struct avrs_ch_pkt_session{
    uint8_t type; // Operation code or packet type
    byte_t padding[7];
    byte_t args[]; // Operation args in TSD format
} DAP_ALIGN_PACKED avrs_ch_pkt_session_t;



// Content packet
typedef struct avrs_ch_pkt_content{
    uint8_t flow_id;  // Content type
    byte_t padding[3];
    uint32_t content_id; // Content id in session
    byte_t data[]; // Data
} DAP_ALIGN_PACKED avrs_ch_pkt_content_t;

#define AVRS_CH_PKT_CONTENT_TYPE_ACTION_REQUEST      0x01
#define AVRS_CH_PKT_CONTENT_TYPE_ACTION_RESPONSE     0x02
#define AVRS_CH_PKT_CONTENT_TYPE_STATE               0x03
#define AVRS_CH_PKT_CONTENT_TYPE_METADATA            0x04
#define AVRS_CH_PKT_CONTENT_TYPE_INFO                0x05
#define AVRS_CH_PKT_CONTENT_TYPE_AUDIO               0x10
#define AVRS_CH_PKT_CONTENT_TYPE_VIDEO               0x11

typedef struct avrs_ch_pkt_retcode{
    int32_t msgnum,                                                       /* A numeric code of a retcode/message */
            msglen;                                                     /* Length of the text representative of the message */
    char    msg[];                                                      /* Text string of the message */
} avrs_ch_pkt_retcode_t;


int avrs_ch_pkt_send_retcode_unsafe(dap_stream_ch_t * a_ch, int a_code, const char * a_text);
int avrs_ch_pkt_send_cluster_unsafe(dap_stream_ch_t * a_ch, uint8_t a_type, const void * a_args, size_t a_args_size );
int avrs_ch_pkt_send_content_unsafe(dap_stream_ch_t * a_ch, uint8_t a_flow_id, uint32_t a_content_id, const void *a_data, size_t a_data_size);

int avrs_ch_pkt_send_retcode_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid, int a_code, const char * a_text);
int avrs_ch_pkt_send_cluster_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const void * a_args, size_t a_args_size );
int avrs_ch_pkt_send_content_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_flow_id, uint32_t a_content_id, const void *a_data, size_t a_data_size);

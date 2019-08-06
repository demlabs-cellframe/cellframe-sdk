/*
 * Authors:
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe
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

#ifdef __cplusplus
extern "C" {
#endif

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#define MAX_IP_STR_LEN 15
#define DAP_ADRESS_UNDEFINED (uint64_t)-1

typedef enum {
    // like in rtnetlink defines
    IP_ADDR_ADD = RTM_NEWADDR,
    IP_ADDR_REMOVE,
    IP_ROUTE_ADD = RTM_NEWROUTE,
    IP_ROUTE_REMOVE,
    IP_LINK_NEW = RTM_NEWLINK,
    IP_LINK_DEL
} dap_network_monitor_notification_type_t;

typedef struct {
    dap_network_monitor_notification_type_t type;
    union {
        struct {
            char interface_name[IF_NAMESIZE];
            char s_ip[MAX_IP_STR_LEN + 1];
            uint32_t ip; // inet_ntoa(*((struct in_addr *)&ipaddr)) for cast to char*
        } addr; // for IP_ADDR_ADD, IP_ADDR_REMOVE
        struct {
            uint64_t destination_address; // 64 bit for checking -1 like not filled variable
            char s_destination_address[MAX_IP_STR_LEN + 1];
            uint64_t gateway_address;
            char s_gateway_address[MAX_IP_STR_LEN + 1];
            uint8_t protocol;
            uint8_t netmask;
        } route; // for IP_ROUTE_ADD, IP_ROUTE_REMOVE
        struct {
            char interface_name[IF_NAMESIZE];
            bool is_up;
            bool is_running;
        } link; // for RTM_NEWLINK, RTM_DELLINK
    };
} dap_network_notification_t;

typedef void (*dap_network_monitor_notification_callback_t)
              (const dap_network_notification_t notification);

/**
 * @brief dap_network_monitor_init
 * @param callback
 * @details starts network monitorting
 * @return 0 if successful
 */
int dap_network_monitor_init(dap_network_monitor_notification_callback_t callback);

/**
 * @brief dap_network_monitor_deinit
 */
void dap_network_monitor_deinit(void);

#ifdef __cplusplus
}
#endif

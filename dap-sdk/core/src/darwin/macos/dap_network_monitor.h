/*
 * Authors:
 * Anton Isaikin <anton.isaikin@demlabs.net>
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

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CFArray.h>

typedef void (*dap_network_monitor_notification_callback_t)
              (SCDynamicStoreRef store, CFArrayRef changedKeys, void *info);
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

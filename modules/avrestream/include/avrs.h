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
#include "dap_common.h"
#include "dap_hash.h"

// Role in cluster, could be combination of different roles at same time
typedef uint16_t avrs_role_t;

// Client can only join to the cluster
#define AVRS_ROLE_CLIENT               0x0001
// Host owns cluster and can operate it as he wants
#define AVRS_ROLE_HOST                 0x0002
// Operator has limited set of permissions for cluster operations
#define AVRS_ROLE_OPERATOR             0x0004
// Server accepts connections from clients, exchanges with content info
// and provide service for others
#define AVRS_ROLE_SERVER               0x0100
// Balancer split connections and content between servers
#define AVRS_ROLE_BALANCER             0x0200
//
#define AVRS_ROLE_ALL                  0xFFFF


#define AVRS_SUCCESS                         0x00000000
#define AVRS_ERROR_ARG_INCORRECT             0x00000001
#define AVRS_ERROR_SIGN_NOT_PRESENT          0x000000f0
#define AVRS_ERROR_SIGN_INCORRECT            0x000000f1
#define AVRS_ERROR_SIGN_ALIEN                0x000000f2
#define AVRS_ERROR_CLUSTER_WRONG_REQUEST     0x00000101
#define AVRS_ERROR_CLUSTER_NOT_FOUND         0x00000102

#define AVRS_ERROR_CONTENT_UNAVAILBLE        0x00000200
#define AVRS_ERROR_CONTENT_NOT_FOUND         0x00000201
#define AVRS_ERROR_CONTENT_INFO_CORRUPTED    0x00000202
#define AVRS_ERROR_CONTENT_CORRUPTED         0x00000203
#define AVRS_ERROR_CONTENT_FLOW_WRONG_ID     0x00000210

#define AVRS_ERROR_MEMBER_NOT_FOUND          0x00000300
#define AVRS_ERROR_MEMBER_SECURITY_ISSUE     0x00000301
#define AVRS_ERROR_MEMBER_INFO_PROBLEM       0x00000302

#define AVRS_ERROR_SESSION_WRONG_REQUEST     0x00000400
#define AVRS_ERROR_SESSION_NOT_OPENED        0x00000401
#define AVRS_ERROR_SESSION_ALREADY_OPENED    0x00000402
#define AVRS_ERROR_SESSION_CONTENT_ID_WRONG  0x00000404

#define AVRS_ERROR                           0xffffffff

enum    {
        DAP_AVRS$K_CH_SIGNAL = 'A',                                     /* AVRS Signaling channnel */
        DAP_AVRS$K_CH_RETCODE = 'r',                                    /* Channel to return a result of request processing */
        DAP_AVRS$K_CH_CLUSTER = 'C',                                    /* Channel for AVRS's Cluster related requests */
        DAP_AVRS$K_CH_CONTENT = 'c',                                    /* Channel for AVRS's Content related requests */
        DAP_AVRS$K_CH_SESSION = 'S',                                    /* Channel for AVRS's Session related requests */

};


extern int g_avrs_debug_more;

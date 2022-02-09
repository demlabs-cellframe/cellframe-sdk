/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "dap_strfuncs.h"
#include "rand/dap_rand.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_stream.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_net_srv.h"
/*
 * Init service client
 * l_uid service id
 * a_callback_client_success callback to start client service
 */
//
int dap_chain_net_srv_remote_init(dap_chain_net_srv_uid_t a_uid,
        dap_chain_net_srv_callback_data_t a_callback_request,
        dap_chain_net_srv_callback_data_t a_callback_response_success,
        dap_chain_net_srv_callback_data_t a_callback_response_error,
        dap_chain_net_srv_callback_data_t a_callback_receipt_next_success,
        dap_chain_net_srv_callback_data_t a_callback_client_success,
        dap_chain_net_srv_callback_sign_request_t a_callback_client_sign_request,
        void *a_inhertor)
{
    dap_chain_net_srv_t *l_srv_custom = dap_chain_net_srv_get(a_uid);
    if(!l_srv_custom) {
        l_srv_custom = dap_chain_net_srv_add(a_uid, a_callback_request,
                a_callback_response_success, a_callback_response_error,
                a_callback_receipt_next_success);
    }
    l_srv_custom->callback_client_success = a_callback_client_success;
    l_srv_custom->callback_client_sign_request = a_callback_client_sign_request;
    if(a_inhertor)
        l_srv_custom->_inhertor = a_inhertor;
    return 0;
}



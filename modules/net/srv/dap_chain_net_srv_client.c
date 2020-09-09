/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_common.h"

#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"


#define LOG_TAG "dap_chain_net_srv_client"

/*
 * Init service client
 * l_uid service id
 * a_callback_client_success callback to start client service
 */
//
int dap_chain_net_srv_client_init(dap_chain_net_srv_uid_t a_uid,
        dap_chain_net_srv_callback_data_t a_callback_request,
        dap_chain_net_srv_callback_data_t a_callback_response_success,
        dap_chain_net_srv_callback_data_t a_callback_response_error,
        dap_chain_net_srv_callback_data_t a_callback_receipt_next_success,
        dap_chain_net_srv_callback_data_t a_callback_client_success,
        dap_chain_net_srv_callback_sign_request_t a_callback_client_sign_request,
        void *a_inhertor) {

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

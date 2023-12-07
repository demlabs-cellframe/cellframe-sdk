/*
* Authors:
* Roman Padenkov <roman.padenkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2023-2024
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

#include "dap_chain_net_srv_request.h"

static struct order_add_request *s_order_add_request_init()
{
    struct order_add_request *l_order_add_request = DAP_NEW_Z(struct order_add_request);
    if(!l_order_add_request){
        return NULL;
    }
    l_order_add_request->worker = dap_events_worker_get_auto();
    l_order_add_request->from_http = true;
    l_order_add_request->response = 0;
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#ifdef DAP_OS_DARWIN
    struct timespec ts;
    ts.tv_sec = 10;
    ts.tv_nsec = 10;
    pthread_cond_timedwait_relative_np(&l_order_add_request->wait_cond, &l_order_add_request->wait_mutex,
                                       &ts);
#else
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&l_order_add_request->wait_cond, &attr);
    pthread_mutex_init(&l_order_add_request->wait_mutex, NULL);
    return l_order_add_request;
}

static void s_order_add_request_deinit (struct order_add_request *a_order_add_request)
{
    pthread_cond_destroy(&a_order_add_request->wait_cond);
    pthread_mutex_destroy(&a_order_add_request->wait_mutex);
    сделать ниже
    /////DAP_DEL_Z(a_order_add_request->link_info);
}

static int s_order_request_wait(struct order_add_request *a_order_add_request, int a_timeout_ms){

    int ret = -1;
    pthread_mutex_lock(&a_order_add_request->wait_mutex);
    if(a_order_add_request->response)
    {
        pthread_mutex_unlock(&a_order_add_request->wait_mutex);
        return 0;
    }
    struct timespec l_cond_timeout;
    clock_gettime(CLOCK_REALTIME, &l_cond_timeout);
    l_cond_timeout.tv_sec += a_timeout_ms/1000;
    int l_ret_wait = pthread_cond_timedwait(&a_order_add_request->wait_cond, &a_order_add_request->wait_mutex, &l_cond_timeout);
    if(!l_ret_wait) {
        ret = a_order_add_request->response ? 0 : -2;
    } else if(l_ret_wait == ETIMEDOUT) {
        log_it(L_NOTICE,"Wait for status is stopped by timeout");
        ret = -1;
    } else if (l_ret_wait) {
        char l_errbuf[128];
        l_errbuf[0] = '\0';
        strerror_r(l_ret_wait,l_errbuf,sizeof (l_errbuf));
        log_it(L_ERROR, "Pthread condition timed wait returned \"%s\"(code %d)", l_errbuf, l_ret_wait);
        ret = -3;
    }
    pthread_mutex_unlock(&a_order_add_request->wait_mutex);
    return ret;
}

int dap_chain_net_srv_request_send(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *ordert, bool a_sync, int cmd)
{
    enum Cmd{
        ADD,
        UPDATE,
        DEL
    };
    if(!a_net) return -1;

    struct order_add_request *l_order_add_request;


    if(cmd == ADD){
        l_order_add_request = s_order_add_request_init();
        if(!l_order_add_request){
            log_it(L_CRITICAL, "Memory allocation error");
            return -2;
        }

    }
    int ret = 0;
    ret = dap_client_http_request(NULL,a_uplink_addr, a_uplink_port, "POST", "application/json", s_url_service, l_str, strlen(l_str),
                            NULL, dap_json_rpc_response_accepted, func_error, NULL, NULL) == NULL;
}

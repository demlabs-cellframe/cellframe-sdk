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

#include "dap_chain_net_srv.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include "dap_chain_net_srv_stream_session.h"

#define LOG_TAG "dap_stream_ch_chain_net_srv_session"

/**
 * @brief dap_chain_net_srv_stream_session_create
 * @param a_session
 * @return
 */
dap_chain_net_srv_stream_session_t * dap_chain_net_srv_stream_session_create( dap_stream_session_t * a_session)
{
    if (!a_session){
        log_it (L_ERROR, "Session is NULL!");
        return NULL;
    }
    dap_chain_net_srv_stream_session_t * l_session_srv= DAP_NEW_Z(dap_chain_net_srv_stream_session_t);
    a_session->_inheritor = l_session_srv;
    l_session_srv->parent = a_session;
    log_it(L_NOTICE, "created service session");
    return  l_session_srv;
}

/**
 * @brief dap_chain_net_srv_usage_add
 * @param a_srv_session
 * @param a_net
 * @param a_srv
 * @return
 */
dap_chain_net_srv_usage_t* dap_chain_net_srv_usage_add (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                            dap_chain_net_t * a_net, dap_chain_net_srv_t * a_srv)
{
    if ( a_srv_session && a_net && a_srv ){
        dap_chain_net_srv_usage_t * l_ret = DAP_NEW_Z(dap_chain_net_srv_usage_t);
        //l_ret->id = 666;
        randombytes(&l_ret->id, sizeof(l_ret->id));
        l_ret->net = a_net;
        l_ret->service = a_srv;
        pthread_rwlock_init(&l_ret->rwlock,NULL);
        pthread_mutex_lock(&a_srv_session->parent->mutex);
        HASH_ADD_INT( a_srv_session->usages, id,l_ret );
        pthread_mutex_unlock(&a_srv_session->parent->mutex);
        log_it( L_NOTICE, "Added service %s:0x%016"DAP_UINT64_FORMAT_X" , usage id: %d", l_ret->net->pub.name, a_srv->uid.uint64, l_ret->id);
        return l_ret;
    }else{
        log_it( L_ERROR, "Some NULLs was in input");
        return NULL;
    }
}

/**
 * @brief dap_chain_net_srv_usage_delete
 * @param a_srv_session
 * @param a_usage
 * @return
 */
void dap_chain_net_srv_usage_delete (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                               dap_chain_net_srv_usage_t* a_usage)
{
    if ( a_usage->receipt )
        DAP_DELETE( a_usage->receipt );
    if ( a_usage->client ){
        for (dap_chain_net_srv_client_remote_t * l_srv_client = a_usage->client, * tmp = NULL; l_srv_client; ){
            tmp = l_srv_client;
            l_srv_client = l_srv_client->next;
            DAP_DELETE( tmp);
        }


    }
    pthread_mutex_lock(&a_srv_session->parent->mutex);
    HASH_DEL(a_srv_session->usages, a_usage);
    pthread_mutex_unlock(&a_srv_session->parent->mutex);
    DAP_DELETE( a_usage );
}

/**
 * @brief dap_chain_net_srv_usage_find
 * @param a_srv_session
 * @param a_usage_id
 * @return
 */
dap_chain_net_srv_usage_t* dap_chain_net_srv_usage_find_unsafe (dap_chain_net_srv_stream_session_t * a_srv_session,
                                                                             uint32_t a_usage_id)
{
    dap_chain_net_srv_usage_t * l_ret = NULL;
    HASH_FIND_INT(a_srv_session->usages, &a_usage_id, l_ret);
    return  l_ret;
}

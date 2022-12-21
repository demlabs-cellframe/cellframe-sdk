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


#include <pthread.h>
#include <stdint.h>


#include "avrs_cluster.h"
#include "avrs_content.h"

#include "avrs_session.h"
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_stream_worker.h"
#include "uthash.h"


#define LOG_TAG "avrs_session"

static avrs_session_t * s_sessions = NULL;
static pthread_rwlock_t s_sessions_rwlock = PTHREAD_RWLOCK_INITIALIZER;
/**
 * @brief avrs_session_new
 * @param a_cluster
 * @param a_id
 * @return
 */
avrs_session_t * avrs_session_open(avrs_ch_t * a_avrs_ch, dap_hash_fast_t * a_session_id)
{
    assert(a_avrs_ch);
    assert(a_session_id);
    avrs_session_t * l_session = avrs_session_find(a_session_id);
    if(l_session){ // Already present

        // Update its CH links
        l_session->avrs_ch = a_avrs_ch;
        l_session->ch_uuid = a_avrs_ch->ch->uuid;
        l_session->ch_worker_id = a_avrs_ch->ch->stream_worker->worker->id;
        return l_session;
    }

    l_session = DAP_NEW_Z_SIZE(avrs_session_t,sizeof(avrs_session_t));
    l_session->avrs_ch = a_avrs_ch;
    l_session->ch_uuid = a_avrs_ch->ch->uuid;
    l_session->ch_worker_id = a_avrs_ch->ch->stream_worker->worker->id;

    l_session->id = *a_session_id;

    l_session->cluster_id_size_max = 0x0f;
    l_session->cluster = DAP_NEW_Z_SIZE(avrs_cluster_t*,sizeof(avrs_cluster_t*)* l_session->cluster_id_size_max);

    l_session->content_size_max = 0xff;
    l_session->content = DAP_NEW_Z_SIZE(avrs_session_content_t,sizeof(avrs_session_content_t)* l_session->content_size_max);

    pthread_rwlock_wrlock( &s_sessions_rwlock);
    HASH_ADD(hh, s_sessions, id, sizeof(l_session->id), l_session);
    pthread_rwlock_unlock( &s_sessions_rwlock);

    return l_session;
}

/**
 * @brief avrs_session_find
 * @param a_sign_id
 * @return
 */
avrs_session_t * avrs_session_find(dap_hash_fast_t * a_session_id)
{
    avrs_session_t * l_session = NULL;

    pthread_rwlock_rdlock( &s_sessions_rwlock);
    HASH_FIND(hh,s_sessions, a_session_id, sizeof(*a_session_id), l_session);
    pthread_rwlock_unlock( &s_sessions_rwlock);

    return l_session;
}

/**
 * @brief avrs_session_delete
 * @param a_session
 */
void avrs_session_delete(avrs_session_t * a_session)
{
    pthread_rwlock_wrlock( &s_sessions_rwlock);
    HASH_DELETE(hh, s_sessions, a_session);
    pthread_rwlock_unlock( &s_sessions_rwlock);

    DAP_DELETE(a_session->cluster );
    DAP_DELETE(a_session->content );
    DAP_DELETE(a_session);
}

/**
 * @brief avrs_session_content_in_data
 * @param a_session
 * @param a_session_content
 * @param a_flow_id
 * @param a_data
 * @param a_data_size
 * @return
 */
int avrs_session_content_in_data(avrs_session_t *a_session, avrs_session_content_t * a_session_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size)
{
    assert(a_session);

    if(a_flow_id >= a_session_content->content->flows_count){
        avrs_ch_pkt_send_retcode_unsafe(a_session->avrs_ch->ch,
                                 AVRS_ERROR_CONTENT_FLOW_WRONG_ID , "CONTENT_FLOW_ID_TOO_BIG");
        return -10;
    }

    int l_ret = avrs_content_data_push_pipeline(a_session_content->content, a_flow_id, a_data, a_data_size);

    if (l_ret )
        return  log_it(L_ERROR, "[avrs:%p] Can't push data in GST pipeline, code %d", a_session, l_ret), l_ret;


    if ( (l_ret = avrs_content_data_push_sessions_out_mt(a_session_content->content, a_flow_id, a_data, a_data_size)) )
        log_it(L_ERROR, "[avrs:%p] Can't push data in GST pipeline, code %d", a_session, l_ret);

    return l_ret;
}


/**
 * @brief avrs_session_content_postproc
 * @param a_session
 * @param a_session_content
 */
int avrs_session_content_out_prepare(avrs_session_t *a_session,  avrs_session_content_t * a_session_content)
{
    return 0;
}

/**
 * @brief avrs_session_content_postproc
 * @param a_session
 * @param a_session_content
 */
size_t avrs_session_content_out_data_size(avrs_session_t *a_session,  avrs_session_content_t * a_session_content)
{
    return 0;
}

/**
 * @brief avrs_session_content_postproc
 * @param a_session
 * @param a_session_content
 */
uint8_t avrs_session_content_out_pkt_type(avrs_session_t *a_session,  avrs_session_content_t * a_session_content)
{
    return 0;
}

/**
 * @brief avrs_session_content_postproc
 * @param a_session
 * @param a_session_content
 */
size_t avrs_session_content_out_data_copy(avrs_session_t *a_session,  avrs_session_content_t * a_session_content, void * a_pkt_data)
{
    return 0;
}

/**
 * @brief avrs_session_content_postproc
 * @param a_session
 * @param a_session_content
 */
size_t avrs_session_content_out_pkt_next(avrs_session_t *a_session,  avrs_session_content_t * a_session_content)
{
    return 0;
}

/**
 * @brief avrs_session_content_postproc
 * @param a_session
 * @param a_session_content
 */
void avrs_session_content_out_postproc(avrs_session_t *a_session)
{
}

/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifdef _WIN32
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_stream_session.h"

#define LOG_TAG "dap_stream_session"

static dap_stream_session_t *s_sessions = NULL;
static pthread_mutex_t s_sessions_mutex = PTHREAD_MUTEX_INITIALIZER;


/**
 * @brief dap_stream_session_lock
 */
inline void dap_stream_session_lock(void)
{
    pthread_mutex_lock(&s_sessions_mutex);
}

/**
 * @brief dap_stream_session_unlock
 */
inline void dap_stream_session_unlock(void)
{
    pthread_mutex_unlock(&s_sessions_mutex);
}

inline void dap_stream_session_get_list_sessions_unlock(void)
{
    pthread_mutex_unlock(&s_sessions_mutex);
}


void dap_stream_session_init()
{
    log_it(L_INFO,"Init module");
    srand ( time(NULL) );
}

void dap_stream_session_deinit()
{
    dap_stream_session_t *l_stm_sess, *tmp;

    log_it(L_INFO,"Destroy all the sessions");

    pthread_mutex_lock(&s_sessions_mutex);
    HASH_ITER(hh, s_sessions, l_stm_sess, tmp)
    {
        // Clang bug at this, current should change at every loop cycle
        HASH_DEL(s_sessions,l_stm_sess);
        if (l_stm_sess->callback_delete)
            l_stm_sess->callback_delete(l_stm_sess, NULL);

        if (l_stm_sess->_inheritor )
            DAP_DELETE(l_stm_sess->_inheritor);

        DAP_DELETE(l_stm_sess);
    }

    pthread_mutex_unlock(&s_sessions_mutex);
}

/**
 *
 * note: dap_stream_session_get_list_sessions_unlock() must be run after this function
 */
dap_list_t* dap_stream_session_get_list_sessions(void)
{
    dap_list_t *l_list = NULL;
    dap_stream_session_t *current, *tmp;

    pthread_mutex_lock(&s_sessions_mutex);
    HASH_ITER(hh, s_sessions, current, tmp)
        l_list = dap_list_append(l_list, current);

    /* pthread_mutex_lock(&s_sessions_mutex); Don't forget do it some out-of-here !!! */

    return l_list;
}


dap_stream_session_t * dap_stream_session_pure_new (void)
{
dap_stream_session_t *l_stm_sess, *l_stm_tmp;
unsigned int session_id = 0, session_id_new = 0;


    if ( !(l_stm_sess = DAP_NEW_Z(dap_stream_session_t)) )              /* Preallocate new session context */
        return  log_it(L_ERROR, "Cannot alocate memory for a new session context, errno=%d", errno), NULL;

    /*
     * Generate session id, check uniqueness against sessions hash table,
     * add new session id into the table
     */
    pthread_mutex_lock(&s_sessions_mutex);

    do {
        session_id_new = session_id = rand() + rand() * 0x100 + rand() * 0x10000 + rand() * 0x01000000;
        HASH_FIND_INT(s_sessions, &session_id_new, l_stm_tmp);
    } while(l_stm_tmp);

    l_stm_sess->id = session_id;
    HASH_ADD_INT(s_sessions, id, l_stm_sess);
    pthread_mutex_unlock(&s_sessions_mutex);                            /* Unlock ASAP ! */

    /* Prefill session context with data ... */
    pthread_mutex_init(&l_stm_sess->mutex, NULL);
    l_stm_sess->time_created = time(NULL);
    l_stm_sess->create_empty = true;

    log_it(L_INFO, "Created session context [stm_sess:%p, id:%u, ts:%"DAP_UINT64_FORMAT_U"]",  l_stm_sess, l_stm_sess->id, l_stm_sess->time_created);

    return l_stm_sess;
}

dap_stream_session_t * dap_stream_session_new(unsigned int media_id, bool open_preview)
{
    dap_stream_session_t * l_stm_sess = dap_stream_session_pure_new();
    l_stm_sess ->media_id = media_id;
    l_stm_sess ->open_preview = open_preview;
    l_stm_sess ->create_empty = false;

    return l_stm_sess ;
}

/**
 * @brief dap_stream_session_id_mt
 * @param id
 * @return
 */
dap_stream_session_t *dap_stream_session_id_mt( unsigned int id )
{
    dap_stream_session_t *ret;
    dap_stream_session_lock();
    HASH_FIND_INT( s_sessions, &id, ret );
    dap_stream_session_unlock();
    return ret;
}

/**
 * @brief dap_stream_session_id_unsafe
 * @param id
 * @return
 */
dap_stream_session_t *dap_stream_session_id_unsafe( unsigned int id )
{
    dap_stream_session_t *ret;
    HASH_FIND_INT( s_sessions, &id, ret );
    return ret;
}


int dap_stream_session_close_mt(unsigned int id)
{
dap_stream_session_t *l_stm_sess;

    log_it(L_INFO, "Close session id %u ...", id);

    dap_stream_session_lock();
    if ( !(l_stm_sess = dap_stream_session_id_unsafe( id )) )
    {
        dap_stream_session_unlock();
        log_it(L_WARNING, "Session id %u not found", id);

        return -1;
    }

    HASH_DEL(s_sessions, l_stm_sess);
    dap_stream_session_unlock();

    log_it(L_INFO, "Delete session context [stm_sess:%p, id:%u, ts:%"DAP_UINT64_FORMAT_U"]",  l_stm_sess, l_stm_sess->id, l_stm_sess->time_created);

    if (l_stm_sess->callback_delete)
        l_stm_sess->callback_delete(l_stm_sess, NULL);

    DAP_DEL_Z(l_stm_sess->_inheritor);
    if (l_stm_sess->key)
        dap_enc_key_delete(l_stm_sess->key);
    DAP_DEL_Z(l_stm_sess->acl);
    DAP_DEL_Z(l_stm_sess->service_key);
    DAP_DELETE(l_stm_sess);

    return  0;
}


/**
 * @brief dap_stream_session_open
 * @param a_session
 * @return
 */
int dap_stream_session_open(dap_stream_session_t * a_session)
{
    int ret;
    pthread_mutex_lock(&a_session->mutex);
    ret=a_session->opened;
    if(a_session->opened==0) a_session->opened=1;
    pthread_mutex_unlock(&a_session->mutex);
    return ret;
}

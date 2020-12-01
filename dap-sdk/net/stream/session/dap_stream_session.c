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

dap_stream_session_t * sessions=NULL;
pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;
int stream_session_close2(dap_stream_session_t * s);
static void * session_check(void * data);

void dap_stream_session_init()
{
    log_it(L_INFO,"Init module");
    srand ( time(NULL) );
}

void dap_stream_session_deinit()
{
    dap_stream_session_t *current, *tmp;
    log_it(L_INFO,"Destroy all the sessions");
    pthread_mutex_lock(&sessions_mutex);
      HASH_ITER(hh, sessions, current, tmp) {
          HASH_DEL(sessions,current);
          if (current->callback_delete)
              current->callback_delete(current, NULL);
          if (current->_inheritor )
              DAP_DELETE(current->_inheritor);
          DAP_DELETE(current);
      }
    pthread_mutex_unlock(&sessions_mutex);
}

/**
 *
 * note: dap_stream_session_get_list_sessions_unlock() must be run after this function
 */
dap_list_t* dap_stream_session_get_list_sessions(void)
{
    dap_list_t *l_list = NULL;
    dap_stream_session_t *current, *tmp;
    pthread_mutex_lock(&sessions_mutex);
    HASH_ITER(hh, sessions, current, tmp)
    {
        l_list = dap_list_append(l_list, current);
        //dap_chain_net_srv_stream_session_t * l_srv_session = current->_inheritor;
        //if(l_srv_session) {
            //dap_net_stats_t *l_stats = DAP_NEW(dap_net_stats_t);
            //memcpy(l_stats, l_srv_session->stats);
            //l_list = dap_list_append(l_list, l_stats);
        //}
    }
    return l_list;
}

void dap_stream_session_get_list_sessions_unlock(void)
{
    pthread_mutex_unlock(&sessions_mutex);
}

static void * session_check(void * data)
{
    return NULL;
}


dap_stream_session_t * dap_stream_session_pure_new()
{
    dap_stream_session_t * ret=NULL;

    unsigned int session_id=0,session_id_new=0;
    do{
        session_id_new=session_id=rand()+rand()*0x100+rand()*0x10000+rand()*0x01000000;
        HASH_FIND_INT(sessions,&session_id_new,ret);
    }while(ret);
    log_it(L_INFO,"Creating new session id %u",session_id);
    ret=DAP_NEW_Z(dap_stream_session_t);
    pthread_mutex_init(&ret->mutex, NULL);
    ret->id=session_id;
    ret->time_created=time(NULL);
    ret->create_empty=true;
    ret->enc_type = 0x01; // Default encryption type
    log_it(L_DEBUG,"Timestamp %u",(unsigned int) ret->time_created);
    pthread_mutex_lock(&sessions_mutex);
    HASH_ADD_INT(sessions,id,ret);
    pthread_mutex_unlock(&sessions_mutex);
    return ret;
}

dap_stream_session_t * dap_stream_session_new(unsigned int media_id, bool open_preview)
{
    dap_stream_session_t * ret=dap_stream_session_pure_new();
    ret->media_id=media_id;
    ret->open_preview=open_preview;
    ret->create_empty=false;

    return ret;
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
    HASH_FIND_INT( sessions, &id, ret );
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
    HASH_FIND_INT( sessions, &id, ret );
    return ret;
}

/**
 * @brief dap_stream_session_lock
 */
void dap_stream_session_lock()
{
    pthread_mutex_lock(&sessions_mutex);
}

/**
 * @brief dap_stream_session_unlock
 */
void dap_stream_session_unlock()
{
    pthread_mutex_unlock(&sessions_mutex);
}


int dap_stream_session_close_mt(unsigned int id)
{
    log_it(L_INFO,"Close session id %u", id);

//    dap_stream_session_list();
    dap_stream_session_lock();
    dap_stream_session_t *l_s = dap_stream_session_id_unsafe( id );
    if(!l_s) {
        log_it(L_WARNING, "Session id %u not found", id);
        dap_stream_session_unlock();
        return -1;
    }

    int ret = stream_session_close2(l_s);
    dap_stream_session_unlock();
    return ret;
}

int stream_session_close2(dap_stream_session_t * a_session)
{
//    log_it(L_INFO,"Close session");
    HASH_DEL(sessions,a_session);
    if (a_session->callback_delete)
        a_session->callback_delete(a_session, NULL);
    if (a_session->_inheritor )
        DAP_DELETE(a_session->_inheritor);
    DAP_DELETE(a_session);
    return 0;
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

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

      HASH_ITER(hh, sessions, current, tmp) {
          HASH_DEL(sessions,current);
          stream_session_close2(current);
      }
}

void dap_stream_session_list()
{
    dap_stream_session_t *current, *tmp;

    log_it(L_INFO,"=== sessions list ======");

      HASH_ITER( hh, sessions, current, tmp ) {
      log_it(L_INFO,"ID %u session %X", current->id, current);

//          HASH_DEL(sessions,current);
//          stream_session_close2(current);
      }

    log_it(L_INFO,"=== sessions list ======");
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
    HASH_ADD_INT(sessions,id,ret);

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

dap_stream_session_t *dap_stream_session_id( unsigned int id )
{
    dap_stream_session_t *ret;
    HASH_FIND_INT( sessions, &id, ret );

    return ret;
}


int dap_stream_session_close(unsigned int id)
{
    log_it(L_INFO,"Close session id %u", id);

//    dap_stream_session_list();

    dap_stream_session_t *l_s = dap_stream_session_id( id );

    if(!l_s) {
        log_it(L_WARNING, "Session id %u not found", id);
        return -1;
    }

    return stream_session_close2(l_s);
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

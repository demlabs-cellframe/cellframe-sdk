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

#ifndef _STREAM_SESSION_H
#define _STREAM_SESSION_H
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include "uthash.h"

#include "dap_enc_key.h"

typedef enum stream_session_type {STREAM_SESSION_TYPE_MEDIA=0,STREAM_SESSION_TYPE_VPN} stream_session_type_t;
typedef enum stream_session_connection_type {STEAM_SESSION_HTTP = 0, STREAM_SESSION_UDP, STREAM_SESSION_END_TYPE} stream_session_connection_type_t;

struct stream_session {

    bool create_empty;
	unsigned int id;
	unsigned int media_id;

	dap_enc_key_t * key;

	bool open_preview;
	pthread_mutex_t mutex;
	int opened;
	time_t time_created;

    uint8_t enc_type;

    stream_session_connection_type_t conn_type;
    stream_session_type_t type;
	UT_hash_handle hh;

    struct in_addr tun_client_addr;
};
typedef struct stream_session stream_session_t;

extern void stream_session_init();
extern void stream_session_deinit();

extern stream_session_t * stream_session_pure_new();
extern stream_session_t * stream_session_new(unsigned int media_id, bool open_preview);
extern stream_session_t * stream_session_id(unsigned int id);
extern int stream_session_open(stream_session_t * ss); /*Lock for opening for single client , return 0 if ok*/
extern int stream_session_close(unsigned int id);


#endif

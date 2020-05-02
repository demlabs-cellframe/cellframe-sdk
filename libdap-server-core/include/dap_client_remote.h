/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "uthash.h"

#ifndef WIN32
#include <sys/epoll.h>
#include <sys/timerfd.h>
#endif

#ifndef EPOLL_HANDLE
  #ifndef WIN32
    #define EPOLL_HANDLE  int
  #else
    #define EPOLL_HANDLE  HANDLE
    #include "wepoll.h"
  #endif
#endif

typedef char str_ip[16];

typedef struct dap_server dap_server_t;
typedef struct dap_server_thread_s dap_server_thread_t;

struct dap_client_remote;

typedef void (*dap_server_client_callback_t) (struct dap_client_remote *,void * arg); // Callback for specific client operations

#define DAP_CLIENT_REMOTE_BUF 500000
#define CLIENT_ID_SIZE 12

typedef char dap_server_client_id[CLIENT_ID_SIZE];

typedef struct traffic_stats {

  size_t buf_size_total;
  size_t buf_size_total_old; // for calculate speed
  double speed_mbs; // MegaBits per second
} traffic_stats_t;

typedef struct dap_client_remote {

  int socket;
  dap_server_client_id id;

  uint32_t  flags;
  bool no_close;
  bool kill_signal;

  uint16_t port;
  str_ip s_ip;

  uint32_t buf_out_zero_count;
  char buf_in[DAP_CLIENT_REMOTE_BUF]; // Internal buffer for input data

  size_t buf_in_size; // size of data that is in the input buffer

  traffic_stats_t upload_stat;
  traffic_stats_t download_stat;

  char buf_out[DAP_CLIENT_REMOTE_BUF]; // Internal buffer for output data
  size_t buf_out_offset;

  char hostaddr[1024]; // Address
  char service[128];

  size_t buf_out_size; // size of data that is in the output buffer
  struct epoll_event  pevent;

  EPOLL_HANDLE efd;            // Epoll fd
  int tn;             // working thread index

  time_t time_connection;
  time_t last_time_active;

  struct dap_server *server;
  dap_server_thread_t *thread;

  UT_hash_handle hh;
  struct dap_client_remote *next, *prev;
  struct dap_client_remote *knext, *kprev;

  void *_internal;
  void *_inheritor; // Internal data to specific client type, usualy states for state machine

} dap_client_remote_t; // Node of bidirectional list of clients

int   dap_client_remote_init( void ); //  Init clients module
void  dap_client_remote_deinit( void ); // Deinit clients module

dap_client_remote_t *dap_client_remote_create( dap_server_t *sh, int s, dap_server_thread_t *dsth );
dap_client_remote_t *dap_client_remote_find( int sock, dap_server_thread_t *t );

bool dap_client_remote_is_ready_to_read( dap_client_remote_t * sc );
bool dap_client_remote_is_ready_to_write( dap_client_remote_t * sc );
void dap_client_remote_ready_to_read( dap_client_remote_t * sc,bool is_ready );
void dap_client_remote_ready_to_write( dap_client_remote_t * sc,bool is_ready );

size_t dap_client_remote_write( dap_client_remote_t *sc, const void * data, size_t data_size );
size_t dap_client_remote_write_f( dap_client_remote_t *a_client, const char * a_format,... );
size_t dap_client_remote_read( dap_client_remote_t *sc, void * data, size_t data_size );

//void dap_client_remote_remove( dap_client_remote_t *sc, struct dap_server * sh ); // Removes the client from the list
void dap_client_remote_remove( dap_client_remote_t *sc );

void dap_client_remote_shrink_buf_in( dap_client_remote_t * cl, size_t shrink_size );


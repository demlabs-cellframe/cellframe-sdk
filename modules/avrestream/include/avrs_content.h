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
#pragma once
#include <dap_hash.h>
#include <dap_cbuf.h>
#include <dap_events_socket.h>
#include "avrs.h"
#include "avrs_cluster.h"

#include "uthash.h"

typedef struct avrs_session avrs_session_t;
typedef struct avrs_session_content avrs_session_content_t;

typedef enum avrs_content_state
{
    CONTENT_STATE_IDLE   =    0x00,
    CONTENT_STATE_PLAYING =   0x01,
    CONTENT_STATE_PAUSED  =   0x02
} avrs_content_state_t;
typedef uint8_t avrs_content_state_packed_t;

typedef struct avrs_content_session
{
    dap_hash_fast_t session_id;
    uint32_t content_session_id;
    avrs_session_t * session;
    UT_hash_handle hh;
} avrs_content_session_t;

typedef struct avrs_content
{
    dap_guuid_t guuid; // Unique ID
    pthread_rwlock_t rwlock;
    avrs_cluster_t * cluster; // Cluster wich content belongs to
    dap_hash_fast_t owner_hash;
    avrs_cluster_member_t * owner;

    union{ // Type specifics
        union {
            struct // Local file
            {
                char * path;
            } file;
            struct { // Local Flow
#ifdef DAP_OS_DARWIN
                int index; // Video device index
                char * name; // Video device name
#endif
            } flow;
        } local; // Local content
        struct {
            dap_cbuf_t * cbuf; // Circular buffer with streaming data
            union{
                struct { // Remote file

                } file;
                union { // Remote flow
                    struct {
                        avrs_cluster_member_t * member; // Stream comes from cluster member
                        avrs_cluster_t * cluster;
                        avrs_session_t * session;
                    } native;
                    struct {
                        char * URL;
                    } alien;
                } flow;
            };
        } remote;
    } source;
    uint32_t flags;

    char *flows; // Flows - audio, video, command, meta, text and etc
    size_t flows_count; // Flows number

    char ** flow_codecs; // Source codecs name. NULL means need autodetect

    avrs_content_session_t * sessions_out; // Session with content_id for downlinks thats accepting current content


    UT_hash_handle hh;

    byte_t pvt[];
} avrs_content_t;


// Is it live streaming
#define AVRS_CONTENT_FLAG_LIVE         0x00000001
// Has it local source
#define AVRS_CONTENT_FLAG_LOCAL        0x00000002
// Is it native protocol streaming or not
#define AVRS_CONTENT_FLAG_NATIVE       0x00000004
// Is it proxy for other content
#define AVRS_CONTENT_FLAG_PROXY        0x00000008
/**
 * @brief avr_content_state_str
 * @param a_state
 * @return
 */
static inline const char* avr_content_state_str(avrs_content_state_t a_state)
{
    switch(a_state)
    {
        case CONTENT_STATE_IDLE:
            return "IDLE";

        case CONTENT_STATE_PLAYING:
            return "PLAYING";

        case CONTENT_STATE_PAUSED:
            return "PAUSED";

        default:
            return "UNDEFINED";
    }
}

int avrs_content_init();
void avrs_content_deinit();

avrs_content_t * avrs_content_new();
void avrs_content_set_flows(avrs_content_t * a_content, const char * a_flows);
void avrs_content_delete(avrs_content_t * a_content);
int avrs_content_data_push_for_everyone_unsafe(avrs_content_t * a_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size);
int avrs_content_data_push_pipeline( avrs_content_t * a_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size);

int avrs_content_data_push_sessions_out_mt(avrs_content_t * a_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size);

int avrs_content_pipeline_connect(avrs_content_t * a_content, const char * a_gst_out, const char * a_gst_in);

int avrs_content_flow_in_set_caps(avrs_content_t * a_content, uint8_t a_flow_id, const char * a_flow_caps );
char* avrs_content_flow_out_get_caps(avrs_content_t * a_content, uint8_t a_flow_id );

int avrs_content_add_session_out(avrs_content_t * a_content,uint32_t a_content_session_id, avrs_session_t * a_session);

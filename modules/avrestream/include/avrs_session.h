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
#include "avrs_content.h"
#include "dap_stream_ch.h"
#include "uthash.h"
#include <dap_common.h>
#include <dap_hash.h>
#include <dap_enc_key.h>
#include <dap_sign.h>
#include <stdint.h>
#include "avrs.h"
#include "avrs_ch.h"
#include "avrs_content.h"

typedef struct avrs_content avrs_content_t;
typedef struct avrs_cluster avrs_cluster_t;
typedef struct avrs_cluster_member avrs_cluster_member_t;

typedef struct avrs_session_content{
    avrs_content_t *content;
    avrs_content_state_t state;
    uint32_t flags;
} avrs_session_content_t;

#define AVRS_SESSION_CONTENT_FLAG_STREAMING_OUT 0x00000001
#define AVRS_SESSION_CONTENT_FLAG_STREAMING_IN  0x00000002

typedef struct avrs_session{
    dap_hash_fast_t id; // ID is remote client's pkey hash to identifiy strong this

    dap_enc_key_t * enc_key; // If it has its own encryption for p2p streaming without reencoding
    avrs_ch_t * avrs_ch;
    dap_stream_ch_uuid_t ch_uuid;
    uint32_t ch_worker_id;

    // Cluster dynamic array
    avrs_cluster_t ** cluster;
    avrs_cluster_member_t ** cluster_member; // Pointer to its member for this cluster
    size_t cluster_id_size;
    size_t cluster_id_size_max;

    // Content out dynamic array
    avrs_session_content_t * content;
    uint32_t content_size;
    uint32_t content_size_max;


    UT_hash_handle hh;
} avrs_session_t;

avrs_session_t * avrs_session_open(avrs_ch_t * a_avrs_ch,dap_hash_fast_t * a_session_id);
avrs_session_t * avrs_session_find( dap_hash_fast_t * a_session_id);
void avrs_session_delete(avrs_session_t * a_session);

/**
 * @brief avrs_session_get_content
 * @param a_session
 * @param a_content_id
 * @return
 */
static inline avrs_session_content_t * avrs_session_get_content(avrs_session_t *a_session, uint32_t a_content_id)
{
    if(a_content_id < a_session->content_size )
        return &a_session->content[a_content_id];
    else
        return NULL;
}

/**
 * @brief avrs_session_get_cluster
 * @param a_session
 * @param a_cluster_ids
 * @return
 */
static inline avrs_cluster_t * avrs_session_get_cluster(avrs_session_t *a_session, uint32_t a_cluster_id)
{
    if(a_cluster_id < a_session->cluster_id_size_max )
        return a_session->cluster[a_cluster_id];
    else
        return NULL;
}

int avrs_session_content_in_data(avrs_session_t *a_session, avrs_session_content_t * a_session_content, uint8_t a_flow_id,  const void * a_data, size_t a_data_size);
int avrs_session_content_out_prepare(avrs_session_t *a_session,  avrs_session_content_t * a_session_content);
size_t avrs_session_content_out_data_size(avrs_session_t *a_session,  avrs_session_content_t * a_session_content);
uint8_t avrs_session_content_out_pkt_type(avrs_session_t *a_session,  avrs_session_content_t * a_session_content);
size_t avrs_session_content_out_data_copy(avrs_session_t *a_session,  avrs_session_content_t * a_session_content, void * a_pkt_data);
size_t avrs_session_content_out_pkt_next(avrs_session_t *a_session,  avrs_session_content_t * a_session_content);
void avrs_session_content_out_postproc(avrs_session_t *a_session);

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
#include <dap_common.h>
#include <dap_chain_common.h>
#include <dap_hash.h>
#include <dap_list.h>
#include <stdint.h>
#include <pthread.h>
#include "uthash.h"

#include "dap_guiid.h"
#include "avrs.h"

typedef struct avrs_content avrs_content_t;
typedef struct avrs_cluster avrs_cluster_t;

typedef struct avrs_cluster_member_addr{
    dap_chain_net_id_t net_id;
    dap_chain_node_addr_t node_addr;
} DAP_ALIGN_PACKED avrs_cluster_member_addr_t;  // Member ID

#define AVRS_CLUSTER_MEMBER_AVATAR_SIZE_MAX         1024*100
#define AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX    63

typedef struct avrs_cluster_member
{
            dap_hash_fast_t     id;             // Based on its pkey hash
            avrs_cluster_t      *cluster;
    avrs_cluster_member_addr_t  addr;           // Member addr
    avrs_role_t role;

    struct {
        char    name [ AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX  + 1];
        char    name_display[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];
        char    name_second[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];
        char    surname[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];
        char    patronim[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];
        char    title[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];
        char    status[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];

        ssize_t avatar_sz;
        byte_t  *avatar;
    } info;

    UT_hash_handle hh;
} avrs_cluster_member_t;


typedef struct avrs_cluster_member_hh
{
        avrs_cluster_member_t *member;
        UT_hash_handle hh;
} avrs_cluster_member_hh_t;


enum avrs_cluster_setup{
    CLUSTER_SETUP_ROUND_TABLE = 0x01,
    CLUSTER_SETUP_LECTURE = 0x02,
    CLUSTER_SETUP_PANEL_DISCUSSION = 0x03,
    CLUSTER_SETUP_MEETING = 0x04,
};

typedef struct avrs_cluster_options
{
        bool    encrypted;
        char    title[AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX + 1];
        enum    avrs_cluster_setup setup;
    dap_hash_fast_t owner_id; // PKey hash and member id same time
}   avrs_cluster_options_t;

typedef struct avrs_cluster
{
    dap_guuid_t guuid;
    UT_hash_handle hh;

    pthread_rwlock_t rwlock;

    avrs_cluster_options_t options;

    avrs_cluster_member_t * members;

    avrs_cluster_member_hh_t * members_servers;
    avrs_cluster_member_hh_t * members_balancers_list;

    avrs_cluster_member_t * member_requests;

    byte_t pvt[];
} avrs_cluster_t;

// Cluster common funcs
avrs_cluster_t *avrs_cluster_new(avrs_cluster_options_t * a_options);
avrs_cluster_t *avrs_cluster_new_from(dap_guuid_t a_guuid, avrs_cluster_options_t * a_options);
void avrs_cluster_delete(avrs_cluster_t * a_cluster);
avrs_cluster_t *avrs_cluster_find(dap_guuid_t a_guuid);

// Member funcs
int avrs_cluster_member_add(avrs_cluster_t * a_cluster,avrs_cluster_member_t* a_member);
avrs_cluster_member_t* avrs_cluster_member_find(avrs_cluster_t * a_cluster, dap_hash_fast_t * a_member_id);
void avrs_cluster_member_delete(avrs_cluster_member_t * a_member);

/// Member request funcs
int avrs_cluster_member_request_add(avrs_cluster_t * a_cluster,avrs_cluster_member_t* a_member);
avrs_cluster_member_t* avrs_cluster_member_request_find(avrs_cluster_t * a_cluster, dap_hash_fast_t * a_member_id);
void avrs_cluster_member_request_remove(avrs_cluster_t * a_cluster, avrs_cluster_member_t* a_member);

/// Cluster content funcs
int avrs_cluster_content_add(avrs_cluster_t * a_cluster,avrs_content_t * a_content);
int avrs_cluster_content_remove(avrs_content_t * a_content);
avrs_content_t * avrs_cluster_content_find(avrs_cluster_t * a_cluster,dap_guuid_t * a_guiid);

// Return serialized in TSD sections list of all the clusters
size_t avrs_cluster_all_serialize_tsd(void ** a_data, size_t * a_data_size);
// Return serialized in TSD sections list of all content in the cluster
size_t avrs_cluster_content_all_serialize_tsd(avrs_cluster_t * a_cluster, void ** a_data, size_t * a_data_size);

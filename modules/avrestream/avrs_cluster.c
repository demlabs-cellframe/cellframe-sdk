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
#include <uthash.h>

#include <dap_common.h>
#include <dap_list.h>
#include <dap_chain_common.h>
#include <dap_hash.h>
#include <dap_math_ops.h>
#include <dap_sign.h>
#include <dap_uuid.h>
#include <dap_time.h>

#include "avrs.h"
#include "avrs_ch_pkt.h"
#include "avrs_session.h"
#include "avrs_content.h"
#include "avrs_cluster.h"

#define LOG_TAG "avrs_cluster"


typedef struct avrs_cluster_pvt
{
    avrs_content_t * contents;
} avrs_cluster_pvt_t;


avrs_cluster_t * s_clusters = NULL;
pthread_rwlock_t s_clusters_rwlock = PTHREAD_RWLOCK_INITIALIZER;

#define PVT(a)  ( (avrs_cluster_pvt_t *) (a->pvt) )

static inline int s_member_add(avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_hh,  avrs_cluster_member_t* a_member);



inline avrs_cluster_t *avrs_cluster_find(dap_guuid_t a_cluster_id)
{
    avrs_cluster_t * l_ret = NULL;

    pthread_rwlock_rdlock(&s_clusters_rwlock);
    HASH_FIND_PTR(s_clusters,&a_cluster_id, l_ret);
    pthread_rwlock_unlock(&s_clusters_rwlock);

    return l_ret;
}



static inline avrs_cluster_t * s_new(void)
{
    avrs_cluster_t * l_ret = DAP_NEW_Z_SIZE(avrs_cluster_t, sizeof(avrs_cluster_t) + sizeof(avrs_cluster_pvt_t));
    pthread_rwlock_init( &l_ret->rwlock, NULL);
    return l_ret;
}


static inline int s_add(avrs_cluster_t * a_cluster)
{
    avrs_cluster_t * l_check = avrs_cluster_find(a_cluster->guuid);

    if(l_check)
        return -1;

    pthread_rwlock_wrlock(&s_clusters_rwlock);
    HASH_ADD_KEYPTR(hh, s_clusters, &a_cluster->guuid, sizeof(a_cluster->guuid), a_cluster);
    pthread_rwlock_unlock(&s_clusters_rwlock);

    return 0;
}



/**
 * @brief avrs_cluster_new_from
 * @param a_guuid
 * @param a_options
 * @return
 */
inline avrs_cluster_t *avrs_cluster_new_from(dap_guuid_t a_guuid, avrs_cluster_options_t * a_options)
{
    avrs_cluster_t * l_ret = s_new();

    if (a_options)
        l_ret->options = *a_options;

    l_ret->guuid = a_guuid;

    pthread_rwlock_wrlock(&s_clusters_rwlock);
    HASH_ADD_KEYPTR(hh, s_clusters, &l_ret->guuid, sizeof(l_ret->guuid), l_ret);
    pthread_rwlock_unlock(&s_clusters_rwlock);

    return l_ret;
}


/**
 * @brief avrs_cluster_new
 * @param a_options
 * @return
 */
avrs_cluster_t *avrs_cluster_new(avrs_cluster_options_t * a_options)
{
    return avrs_cluster_new_from(dap_guuid_new(), a_options);
}




/**
 * @brief avrs_cluster_delete
 * @param a_cluster
 */
void avrs_cluster_delete(avrs_cluster_t * a_cluster)
{
avrs_content_t * l_content, * l_tmp;

    pthread_rwlock_wrlock(&s_clusters_rwlock);

    HASH_ITER(hh, PVT(a_cluster)->contents, l_content, l_tmp){
        l_content->cluster = NULL;
        avrs_content_delete(l_content);
        HASH_DELETE(hh, PVT(a_cluster)->contents, l_content);
    }

    HASH_DELETE(hh, s_clusters, a_cluster);

    pthread_rwlock_unlock(&s_clusters_rwlock);
}

/**
 * @brief s_member_add
 * @param a_cluster
 * @param a_hh
 * @param a_member
 * @return
 */
static inline int s_member_add(avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_hh,  avrs_cluster_member_t* a_member)
{
    avrs_cluster_member_t * l_check = NULL;
    char l_member_id_str[DAP_CHAIN_HASH_FAST_STR_SIZE];

    pthread_rwlock_wrlock(&a_cluster->rwlock);
    HASH_FIND(hh,a_hh,&a_member->id, sizeof(a_member->id), l_check);
    if(l_check)
    {
        pthread_rwlock_unlock(&a_cluster->rwlock);                      /* Unlock ASAP !!! */

        dap_hash_fast_to_str(&a_member->id, l_member_id_str, sizeof(l_member_id_str));
        log_it(L_WARNING, "Trying to add member %s but its already present in cluster ", l_member_id_str);

        return -EEXIST;
    }


    a_member->cluster = a_cluster;
    HASH_ADD(hh, a_hh, id, sizeof(a_member->id), a_member);
    pthread_rwlock_unlock(&a_cluster->rwlock);

    return 0;
}

/**
 * @brief avrs_cluster_member_add
 * @param a_cluster
 * @param a_member
 * @return
 */
int avrs_cluster_member_add(avrs_cluster_t * a_cluster,avrs_cluster_member_t* a_member)
{
    return s_member_add(a_cluster, a_cluster->members, a_member);
}

/**
 * @brief avrs_cluster_member_request_add
 * @param a_cluster
 * @param a_member
 * @return
 */
int avrs_cluster_member_request_add(avrs_cluster_t * a_cluster,avrs_cluster_member_t* a_member)
{
    return s_member_add(a_cluster, a_cluster->member_requests , a_member);

}

/**
 * @brief avrs_cluster_member_delete
 * @param a_member
 */
void avrs_cluster_member_delete(avrs_cluster_member_t * a_member)
{
    pthread_rwlock_wrlock(&a_member->cluster->rwlock);
    HASH_DELETE(hh, a_member->cluster->members, a_member);
    pthread_rwlock_unlock(&a_member->cluster->rwlock);

    if (a_member->info.avatar)
        DAP_DELETE(a_member->info.avatar);


    DAP_DELETE(a_member);
    // TODO disconnect member when remove and send updates to other cluster members
    // to let them to do the same
}

/**
 * @brief avrs_cluster_member_find
 * @param a_cluster
 * @param a_member_id
 * @return
 */
avrs_cluster_member_t* avrs_cluster_member_find(avrs_cluster_t * a_cluster, dap_hash_fast_t * a_member_id)
{
    avrs_cluster_member_t * l_member = NULL;

    pthread_rwlock_rdlock(&a_cluster->rwlock);
    HASH_FIND(hh,a_cluster->members,a_member_id, sizeof(*a_member_id), l_member);
    pthread_rwlock_unlock(&a_cluster->rwlock);

    return l_member;
}

/**
 * @brief avrs_cluster_member_request_find
 * @param a_cluster
 * @param a_member_id
 * @return
 */
avrs_cluster_member_t* avrs_cluster_member_request_find(avrs_cluster_t * a_cluster, dap_hash_fast_t * a_member_id)
{
    avrs_cluster_member_t * l_member = NULL;

    pthread_rwlock_rdlock(&a_cluster->rwlock);
    HASH_FIND(hh,a_cluster->member_requests,a_member_id, sizeof(*a_member_id), l_member);
    pthread_rwlock_unlock(&a_cluster->rwlock);

    return l_member;
}

/**
 * @brief avrs_cluster_member_request_remove
 * @param a_cluster
 * @param a_member
 */
void avrs_cluster_member_request_remove(avrs_cluster_t * a_cluster, avrs_cluster_member_t* a_member)
{
    pthread_rwlock_wrlock(&a_cluster->rwlock);
    HASH_DELETE(hh,a_cluster->member_requests, a_member);
    pthread_rwlock_unlock(&a_cluster->rwlock);
}

/**
 * @brief avrs_cluster_content_add
 * @param a_cluster
 * @param a_content
 * @return
 */
int avrs_cluster_content_add(avrs_cluster_t * a_cluster,avrs_content_t * a_content)
{
    if ( ! avrs_cluster_content_find (a_content->cluster, &a_content->guuid) )
        return -1;

    pthread_rwlock_wrlock(&a_content->rwlock);
    pthread_rwlock_wrlock(&a_cluster->rwlock);

    HASH_ADD(hh, PVT(a_cluster)->contents, guuid, sizeof(a_content->guuid), a_content);
    a_content->cluster = a_cluster;

    pthread_rwlock_unlock(&a_cluster->rwlock);
    pthread_rwlock_unlock(&a_content->rwlock);

    return 0;
}

/**
 * @brief avrs_cluster_content_remove
 * @param a_content
 * @return
 */
int avrs_cluster_content_remove(avrs_content_t * a_content)
{
    int l_ret = 0;
    pthread_rwlock_rdlock(&a_content->rwlock);

    if(! a_content->cluster){
        l_ret = -1;
        goto lb_ret;
    }

    pthread_rwlock_unlock(&a_content->rwlock);
    if ( ! avrs_cluster_content_find (a_content->cluster, &a_content->guuid) ){
        l_ret = -2;
        goto lb_ret;
    }

    pthread_rwlock_wrlock(&a_content->rwlock);
    pthread_rwlock_wrlock(&a_content->cluster->rwlock);

    HASH_DELETE(hh, PVT(a_content->cluster)->contents, a_content );

    pthread_rwlock_unlock(&a_content->cluster->rwlock);
    a_content->cluster = NULL;

lb_ret:
    pthread_rwlock_unlock(&a_content->rwlock);
    return l_ret;
}

/**
 * @brief avrs_cluster_content_find
 * @param a_guuid
 * @return
 */
avrs_content_t * avrs_cluster_content_find(avrs_cluster_t * a_cluster,dap_guuid_t * a_content_id)
{
    avrs_content_t * l_ret = NULL;

    pthread_rwlock_rdlock(&a_cluster->rwlock);
    HASH_FIND(hh, PVT(a_cluster)->contents, a_content_id, sizeof(*a_content_id), l_ret );
    pthread_rwlock_unlock(&a_cluster->rwlock);

    return l_ret;
}

/**
 * @brief avrs_cluster_all_serialize_tsd
 * @param a_data
 * @param a_data_size
 * @return Number of serialized clusters
 */
size_t avrs_cluster_all_serialize_tsd(void ** a_data, size_t * a_data_size)
{
    assert(a_data);
    assert(a_data_size);
    size_t l_clusters_count = 0, l_offset = 0;
    avrs_cluster_t * l_cluster , * l_tmp;

    pthread_rwlock_rdlock(&s_clusters_rwlock);
    HASH_ITER(hh, s_clusters, l_cluster, l_tmp){
        // Calc new tsd section size
        size_t l_tsd_size = sizeof(dap_tsd_t) + sizeof (dap_guuid_t);

        // Realloc output data and check for OOEM
        a_data = DAP_REALLOC(*a_data, *a_data_size + l_tsd_size);
        if( !a_data){
            log_it(L_CRITICAL, "Out of memory, stopped with cluster list forming on position %zd", l_clusters_count);
            return l_clusters_count;
        }
        // Fill new data chunk with values
        dap_tsd_t * l_tsd = (dap_tsd_t*) ((byte_t*)(*a_data) + l_offset);
        l_tsd->type = AVRS_CH_PKT_CLUSTER_ARG_ID;
        memcpy(l_tsd->data, &l_cluster->guuid, sizeof(l_cluster->guuid) );
        // Move data set and over the iteration
        l_offset += l_tsd_size;
    }
    pthread_rwlock_unlock(&s_clusters_rwlock);
    return l_clusters_count;
}

/**
 * @brief avrs_cluster_content_all_serialize_tsd
 * @param a_cluster
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t avrs_cluster_content_all_serialize_tsd(avrs_cluster_t * a_cluster, void ** a_data, size_t * a_data_size)
{
    assert(a_data);
    assert(a_data_size);
    size_t l_clusters_count = 0, l_offset = 0;
    avrs_content_t * l_content , * l_tmp;

    pthread_rwlock_rdlock(&a_cluster->rwlock);
    HASH_ITER(hh, PVT(a_cluster)->contents , l_content, l_tmp)
    {
        // Calc new tsd section size
        size_t l_tsd_size = sizeof(dap_tsd_t) + sizeof (dap_guuid_t);

        // Realloc output data and check for OOEM
        a_data = DAP_REALLOC(*a_data, *a_data_size + l_tsd_size);
        if( !a_data){
            log_it(L_CRITICAL, "Out of memory, stopped with cluster list forming on position %zd", l_clusters_count);
            return l_clusters_count;
        }

        // Fill new data chunk with values
        dap_tsd_t * l_tsd = (dap_tsd_t*) ((byte_t*)(*a_data) + l_offset);
        l_tsd->type = AVRS_CH_PKT_CLUSTER_ARG_CONTENT_ID;
        memcpy(l_tsd->data, &l_content->guuid, sizeof(l_content->guuid ) );
        // Move data set and over the iteration
        l_offset += l_tsd_size;
    }

    pthread_rwlock_unlock(&a_cluster->rwlock);
    return l_clusters_count;
}

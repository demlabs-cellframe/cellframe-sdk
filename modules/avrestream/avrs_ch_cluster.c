/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Demlabs Inc   https://demlabs.net
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
#include <stdio.h>

#include "dap_common.h"
#include "dap_uuid.h"
#include "dap_tsd.h"

#include "avrs.h"
#include "avrs_ch_pkt.h"
#include "avrs_cluster.h"
#include "avrs_ch_cluster.h"
#include "avrs_session.h"
#include "avrs_content.h"
#include "dap_guiid.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"

#define LOG_TAG "avrs_ch_cluster"

typedef int (*tsd_parse_callback_t)(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, size_t a_tsd_offset,avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size, dap_guuid_t a_guuid, bool a_is_guuid, void * a_arg);

typedef int (*tsd_parse_member_id_and_check_sign_callback_t)(avrs_ch_t *a_avrs_ch, dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster,  dap_hash_fast_t * a_member_id, void * a_arg);
typedef int (*tsd_parse_member_and_check_callback_t)(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_member, avrs_cluster_member_t * a_member_to, dap_hash_fast_t * a_member_to_id, void * a_arg);

typedef int (*tsd_parse_member_content_and_check_callback_t)(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_member, avrs_cluster_member_t * a_member_to, dap_hash_fast_t * a_member_to_id,
                                                             avrs_content_t * a_content, dap_guuid_t a_content_id, void * a_arg);

// Cluster callbacks
static avrs_ch_pkt_cluster_callback_t * s_pkt_in_cluster_callbacks = NULL;
static size_t s_pkt_in_cluster_callbacks_size = 0;



// Parse callback helpers
static int s_tsd_parse_callback_type_create(avrs_ch_t *a_avrs_ch, dap_tsd_t* a_tsd, size_t a_tsd_offset, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size, dap_guuid_t a_guuid, bool a_is_guuid, void * a_arg);
static int s_tsd_parse_callback_type_member_request_add(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster, dap_hash_fast_t * a_member_id, void * a_arg);
static int s_tsd_parse_callback_type_member_approve(avrs_ch_t *a_avrs_ch,dap_tsd_t* l_tsd, avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_member, avrs_cluster_member_t * a_member_to, dap_hash_fast_t * a_member_to_id, void * a_arg);
static int s_tsd_parse_callback_type_content_add(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_member, avrs_cluster_member_t * a_member_to, dap_hash_fast_t * a_member_to_id, void * a_arg);

static int s_parse_cluster_pkt_get_member_and_check_callback_wrap(avrs_ch_t *a_avrs_ch, dap_tsd_t* l_tsd, avrs_cluster_t * a_cluster,  dap_hash_fast_t * a_member_id, void * a_arg);

// Smaller routines
static int s_tsd_parse_member_info(avrs_ch_t *a_avrs_ch, char *a_member_info_ptr, const char * a_member_info_name, const char * a_member_info_name_error, dap_tsd_t * a_tsd);


// Check and parse functions
static inline int s_parse_cluster_pkt_and_verify(avrs_ch_t *a_avrs_ch, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size, dap_hash_fast_t * a_member_id,
                    dap_guuid_t * a_guuid, bool *a_is_guuid, tsd_parse_callback_t a_parse_callback, void * a_arg);

static inline int s_parse_cluster_pkt_get_member_id_and_verify_sign(avrs_ch_t *a_avrs_ch,avrs_cluster_t ** a_cluster, dap_hash_fast_t * a_member_id, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                                    tsd_parse_member_id_and_check_sign_callback_t a_parse_callback, void * a_arg);
static inline avrs_cluster_t * s_parse_cluster_pkt_and_verify_owner(avrs_ch_t *a_avrs_ch, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,tsd_parse_member_id_and_check_sign_callback_t a_parse_callback, void * a_arg);

static inline int s_parse_cluster_pkt_get_member_and_check(avrs_ch_t *a_avrs_ch, avrs_cluster_t ** a_cluster,  avrs_cluster_member_t **a_member_op, avrs_cluster_member_t **a_member_to, dap_hash_fast_t * a_member_to_id,
                                                           avrs_role_t a_roles,bool a_pass_if_himself,
                                                           avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                                    tsd_parse_member_and_check_callback_t a_parse_callback, void * a_arg);
static inline int s_parse_cluster_pkt_get_member_content_check(avrs_ch_t *a_avrs_ch, avrs_cluster_t ** a_cluster, avrs_cluster_member_t **a_member_op, avrs_content_t **a_content,avrs_role_t a_roles, bool a_pass_if_itself,
                                                           avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                                    tsd_parse_member_content_and_check_callback_t a_parse_callback, void * a_arg);


/**
 * @brief avrs_ch_pkt_in_cluster_add_callback
 * @param a_callback
 */
void avrs_ch_pkt_in_cluster_add_callback(avrs_ch_pkt_cluster_callback_t a_callback)
{
    s_pkt_in_cluster_callbacks_size++;
    if (s_pkt_in_cluster_callbacks)
        s_pkt_in_cluster_callbacks = DAP_REALLOC(s_pkt_in_cluster_callbacks, s_pkt_in_cluster_callbacks_size * sizeof(avrs_ch_pkt_cluster_callback_t));
    else
        s_pkt_in_cluster_callbacks = DAP_NEW_SIZE(avrs_ch_pkt_cluster_callback_t, s_pkt_in_cluster_callbacks_size * sizeof(avrs_ch_pkt_cluster_callback_t));

    s_pkt_in_cluster_callbacks[s_pkt_in_cluster_callbacks_size-1] = a_callback;

}

/**
 * @brief s_pkt_in_cluster
 * @param a_avrs_ch
 * @param a_pkt
 * @param a_pkt_args_size
 */
void avrs_ch_pkt_in_cluster(avrs_ch_t * a_avrs_ch, avrs_ch_pkt_cluster_t *a_pkt, size_t a_pkt_args_size)
{
    avrs_cluster_t * l_cluster = NULL;

    switch( a_pkt->type ){
        case AVRS_CH_PKT_CLUSTER_TYPE_CREATE:{
            dap_hash_fast_t l_member_id = {};
            dap_guuid_t l_cluster_guuid={0};
            bool l_is_guuid = false;
            avrs_cluster_options_t l_cluster_opts={};

            int l_parse_ret = s_parse_cluster_pkt_and_verify(a_avrs_ch, a_pkt, a_pkt_args_size,
                                    &l_member_id, &l_cluster_guuid, &l_is_guuid, s_tsd_parse_callback_type_create, &l_cluster_opts);
            if( l_parse_ret) {
                log_it(L_WARNING, "Parse cluster pkt error, code %d", l_parse_ret);
                break;
            }

            l_cluster = l_is_guuid ? avrs_cluster_new_from(l_cluster_guuid, &l_cluster_opts) :avrs_cluster_new(&l_cluster_opts);
            dap_tsd_t * l_tsd_id = dap_tsd_create_scalar(AVRS_CH_PKT_CLUSTER_ARG_ID,l_cluster->guuid);
            avrs_ch_pkt_send_cluster_unsafe(a_avrs_ch->ch, AVRS_CH_PKT_CLUSTER_TYPE_INFO,l_tsd_id, dap_tsd_size(l_tsd_id) );
            DAP_DELETE(l_tsd_id);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_SUCCESS, "SUCCESS");
        } break;


        case AVRS_CH_PKT_CLUSTER_TYPE_DESTROY:{
            l_cluster = s_parse_cluster_pkt_and_verify_owner(a_avrs_ch, a_pkt, a_pkt_args_size,NULL, NULL);
            // No correct GUUID was present or no sign or smth else goes wrong
            if( !l_cluster)
                break;
            avrs_cluster_delete(l_cluster);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_SUCCESS, "SUCCESS");
        } break;
        case AVRS_CH_PKT_CLUSTER_TYPE_CHANGE:{
            l_cluster = s_parse_cluster_pkt_and_verify_owner(a_avrs_ch, a_pkt, a_pkt_args_size,NULL, NULL);
            // No correct GUUID was present or no sign or smth else goes wrong
            if( !l_cluster)
                break;
        } break;
        case AVRS_CH_PKT_CLUSTER_TYPE_INFO:{
        } break;
        case AVRS_CH_PKT_CLUSTER_TYPE_LIST_REQUEST:{
            void * l_data_out = NULL;
            size_t l_data_out_size = 0;
            size_t l_clusters_count = avrs_cluster_all_serialize_tsd(&l_data_out, &l_data_out_size);

            char l_ret_str[32];
            l_ret_str[0] = 0;

            snprintf(l_ret_str, sizeof(l_ret_str),"CLUSTERS_COUNT_%zd", l_clusters_count);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_SUCCESS , l_ret_str);

            if( l_data_out && l_data_out_size){
                avrs_ch_pkt_send_cluster_unsafe(a_avrs_ch->ch,
                                                AVRS_CH_PKT_CLUSTER_TYPE_LIST_RESPONSE ,
                                                l_data_out,l_data_out_size );
                DAP_DELETE(l_data_out);
            }

        } break;

        case AVRS_CH_PKT_CLUSTER_TYPE_LIST_RESPONSE:{
        }break;

        case AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REQUEST_ADD:{
            dap_hash_fast_t l_member_id = {};
            avrs_cluster_member_t * l_member = DAP_NEW_Z(avrs_cluster_member_t);

            // No correct GUUID was present or no sign or smth else goes wrong
            if( s_parse_cluster_pkt_get_member_id_and_verify_sign(a_avrs_ch, &l_cluster, &l_member_id,a_pkt,a_pkt_args_size,s_tsd_parse_callback_type_member_request_add, l_member) != 0){
                avrs_cluster_member_delete(l_member);
                break;
            }
            memcpy(&l_member->id, &l_member_id, sizeof(l_member->id));

            // If nothing bad, we add in member join requests
            avrs_cluster_member_request_add(l_cluster, l_member);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_SUCCESS, "SUCCESS");

        } break;
        case AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REQUEST_APPROVE:{
            avrs_cluster_member_t * l_member_op = NULL; // member that signs this packet
            dap_hash_fast_t l_member_to_id = {};
            if(s_parse_cluster_pkt_get_member_and_check(a_avrs_ch, &l_cluster, &l_member_op,NULL,&l_member_to_id,
                                                        AVRS_ROLE_HOST | AVRS_ROLE_OPERATOR, false,
                                                        a_pkt, a_pkt_args_size,NULL, NULL) != 0 ){
                log_it(L_WARNING,"Some checks haven't passed");
                break;
            }
            assert (l_cluster);
            assert (l_member_op);

            if ( dap_hash_fast_is_blank(&l_member_to_id)){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_MEMBER_NOT_FOUND, "CLUSTER_MEMBER_APPROVE_ID_NOT_PRESENT");
                break;
            }

            avrs_cluster_member_t * l_member_to_approve = avrs_cluster_member_request_find( l_cluster, &l_member_to_id);

            if( !l_member_to_approve){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_MEMBER_NOT_FOUND, "CLUSTER_MEMBER_APPROVE_NOT_FOUND");
                break;
            }

            avrs_cluster_member_request_add(l_cluster, l_member_to_approve);
        } break;

        case AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REMOVE:{
            avrs_cluster_member_t * l_member_to_remove = NULL;
            avrs_cluster_member_t * l_member_op = NULL; // member that signs this packet
            if(s_parse_cluster_pkt_get_member_and_check(a_avrs_ch, &l_cluster, &l_member_op,&l_member_to_remove, NULL,
                                                        AVRS_ROLE_HOST | AVRS_ROLE_OPERATOR, true,
                                                        a_pkt, a_pkt_args_size,NULL, NULL) != 0 ){
                log_it(L_WARNING,"Some checks haven't passed or smth is missing in request");
                break;
            }
            assert (l_cluster);
            assert (l_member_op);
            assert (l_member_to_remove);

            avrs_cluster_member_delete(l_member_to_remove);
        } break;

        case AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_ADD:{
            avrs_cluster_member_t * l_member_to = NULL;
            avrs_cluster_member_t * l_member_op = NULL; // member that signs this packet
            avrs_content_t * l_content = avrs_content_new();
            if(s_parse_cluster_pkt_get_member_and_check(a_avrs_ch, &l_cluster, &l_member_op,NULL,NULL,
                                                        AVRS_ROLE_HOST | AVRS_ROLE_OPERATOR| AVRS_ROLE_SERVER, true,
                                                        a_pkt, a_pkt_args_size,s_tsd_parse_callback_type_content_add, l_content) != 0 ){
                log_it(L_WARNING,"Some checks haven't passed or smth is missing in request or wrong");
                avrs_content_delete(l_content);
                break;
            }
            assert (l_cluster);
            assert (l_member_op);
            assert (l_member_to);

            avrs_cluster_content_add( l_cluster, l_content);
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_UPDATE:{
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_DEL:{
            avrs_cluster_member_t * l_member_op = NULL;
            avrs_content_t * l_content = NULL;
            if(s_parse_cluster_pkt_get_member_content_check(a_avrs_ch, &l_cluster, &l_member_op, &l_content,
                                                        AVRS_ROLE_HOST | AVRS_ROLE_OPERATOR | AVRS_ROLE_SERVER, true,
                                                        a_pkt, a_pkt_args_size,NULL, NULL) != 0 ){
                log_it(L_WARNING,"Some checks haven't passed or smth is missing in request");
                break;
            }
            assert (l_cluster);
            assert (l_member_op);
            assert (l_content);
            avrs_content_delete(l_content);
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_LIST_REQUEST:{
            avrs_cluster_member_t * l_member = NULL; // member that signs this packet
            if(s_parse_cluster_pkt_get_member_and_check(a_avrs_ch, &l_cluster, &l_member,NULL, NULL,
                                                        AVRS_ROLE_ALL, false,
                                                        a_pkt, a_pkt_args_size,NULL, NULL) != 0 ){
                log_it(L_WARNING,"Not cluster's member to request the content's list");
                break;
            }
            assert (l_cluster);
            assert (l_member);

            void * l_data_out = NULL;
            size_t l_data_out_size = 0;
            size_t l_clusters_count = avrs_cluster_content_all_serialize_tsd(l_cluster, &l_data_out, &l_data_out_size);

            char l_ret_str[32];
            l_ret_str[0] = 0;

            snprintf(l_ret_str, sizeof(l_ret_str),"CLUSTER_CONTENTS_COUNT_%zd", l_clusters_count);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_SUCCESS , l_ret_str);

            if( l_data_out && l_data_out_size){
                avrs_ch_pkt_send_cluster_unsafe(a_avrs_ch->ch,
                                                AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_LIST_RESPONSE ,
                                                l_data_out,l_data_out_size );
                DAP_DELETE(l_data_out);
            }

        } break;
        case AVRS_CH_PKT_CLUSTER_TYPE_CONTENT_LIST_RESPONSE:{

        } break;
        case AVRS_CH_PKT_CLUSTER_TYPE_BALANCE_REQUEST:{
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_BALANCE_RESPONSE:{
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_ADD:{
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_DEL:{
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_FIND:{
        }break;
        case AVRS_CH_PKT_CLUSTER_TYPE_ROUTE_CHECK:{
        }break;
        default:{

        }
    }
    for(size_t i = 0; i < s_pkt_in_cluster_callbacks_size; i++)
        s_pkt_in_cluster_callbacks[i] (a_avrs_ch,l_cluster, a_pkt, a_pkt_args_size);

}

/**
 * @brief s_tsd_parse_callback_type_create
 * @param a_avrs_ch
 * @param l_tsd
 * @param l_tsd_offset
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_guuid
 * @param a_arg
 */
static int s_tsd_parse_callback_type_create(
                    avrs_ch_t   *a_avrs_ch,
                    dap_tsd_t   *l_tsd,
                    size_t      l_tsd_offset,
        avrs_ch_pkt_cluster_t   *a_pkt,
                    size_t      a_pkt_args_size,
                    dap_guuid_t a_guuid,
                        bool    a_is_guuid,
                        void    *a_arg)
{
    assert(a_arg);
    avrs_cluster_options_t * l_cluster_opts=(avrs_cluster_options_t *) a_arg;
    int     l_sz;

    switch(l_tsd->type)
    {
        case AVRS_CH_PKT_CLUSTER_ARG_TITLE:
            l_sz = MIN( l_tsd->size, AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX);
            memcpy(l_cluster_opts->title, dap_tsd_get_string_const(l_tsd), l_tsd->size );
            l_cluster_opts->title[l_sz] = '\0';

            break;

        case AVRS_CH_PKT_CLUSTER_ARG_SETUP:
            l_cluster_opts->setup = dap_tsd_get_scalar(l_tsd,uint8_t);
            break;

        case AVRS_CH_PKT_CLUSTER_ARG_ENCRYPTED:
            l_cluster_opts->encrypted = dap_tsd_get_scalar(l_tsd,uint8_t);
            break;

        default:
            return -EINVAL; // Code of unknown TSD type
    }
    return 0;
}

/**
 * @brief s_tsd_parse_member_info
 * @param a_avrs_ch
 * @param a_member_info_ptr
 * @param a_tsd
 * @return
 */
static int s_tsd_parse_member_info(avrs_ch_t *a_avrs_ch, char *a_member_info_ptr, const char *a_member_info_name, const char *a_member_info_name_error, dap_tsd_t * a_tsd)
{
    if (a_tsd->size > AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX)
    {
        log_it(L_WARNING, "%s size %u is too big (should be not bigger than %u)", a_member_info_name, a_tsd->size, AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX);
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_MEMBER_INFO_PROBLEM , a_member_info_name_error );
        return -EINVAL;
    }


    memcpy(a_member_info_ptr, dap_tsd_get_string_const(a_tsd), a_tsd->size );
    a_member_info_ptr[a_tsd->size] = '\0';

    return 0;
}

/**
 * @brief s_tsd_parse_callback_type_member_join_request
 * @param a_avrs_ch
 * @param a_tsd
 * @param a_tsd_offset
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_guuid
 * @param a_is_guuid
 * @param a_arg
 * @return
 */
static int s_tsd_parse_callback_type_member_request_add(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster, dap_hash_fast_t * a_member_id, void * a_arg)
{
    avrs_cluster_member_t * l_member = (avrs_cluster_member_t * ) a_arg;
    int l_ret = 0;

    assert(a_tsd);

    switch(a_tsd->type){
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ADDR:
            l_member->addr = dap_tsd_get_scalar(a_tsd, avrs_cluster_member_addr_t);
        break;

        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_STATUS:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.status, "Status", "MEMBER_STATUS_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_TITLE:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.title, "Title", "MEMBER_TITLE_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_DISPLAY_NAME:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.name_display, "Display name", "MEMBER_DISPLAY_NAME_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_NAME:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.name, "Name", "MEMBER_NAME_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SECOND_NAME:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.name_second, "Second name", "MEMBER_SECOND_NAME_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SURNAME:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.surname, "Surname", "MEMBER_SURNAME_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_PATRONIM:
            l_ret = s_tsd_parse_member_info ( a_avrs_ch, l_member->info.patronim, "Patronim", "MEMBER_PATRONIM_SIZE_TOO_BIG", a_tsd);
        break;
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_AVATAR:
            if (a_tsd->size > AVRS_CLUSTER_MEMBER_AVATAR_SIZE_MAX){
                log_it(L_WARNING, "Avatar size %u is too big (should be not bigger than %u)", a_tsd->size, AVRS_CLUSTER_MEMBER_AVATAR_SIZE_MAX);
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_MEMBER_INFO_PROBLEM , "MEMBER_AVATAR_SIZE_TOO_BIG");
                return -110;
            }

            l_member->info.avatar_sz = a_tsd->size;
            l_member->info.avatar = DAP_DUP_SIZE(a_tsd->data, a_tsd->size);
        break;

        default: l_ret = -EINVAL; // Code of unknown TSD type
    }

    return l_ret;
}

/**
 * @brief s_tsd_parse_callback_type_content_add
 * @param a_avrs_ch
 * @param a_tsd
 * @param a_cluster
 * @param a_member
 * @param a_member_to
 * @param a_member_to_id
 * @param a_arg
 * @return
 */
static int s_tsd_parse_callback_type_content_add(
                    avrs_ch_t   *a_avrs_ch,
                    dap_tsd_t   *a_tsd,
                avrs_cluster_t  *a_cluster,
        avrs_cluster_member_t   *a_member,
        avrs_cluster_member_t   *a_member_to,
            dap_hash_fast_t     *a_member_to_id,
                        void    *a_arg)
{
    assert(a_arg);
    avrs_content_t * l_content=(avrs_content_t *) a_arg;

    switch(a_tsd->type){
        case AVRS_CH_PKT_CLUSTER_ARG_CONTENT_ID:
            l_content->guuid = dap_tsd_get_scalar(a_tsd,dap_guuid_t);
            break;

        case AVRS_CH_PKT_CLUSTER_ARG_CONTENT_FLOWS:{
            const char * l_tsd_string = dap_tsd_get_string_const(a_tsd);
            if (dap_strcmp(l_tsd_string, DAP_TSD_CORRUPTED_STRING) != 0 ){
                l_content->flows_count = strlen(l_content->flows);
                l_content->flows = dap_strdup(l_tsd_string);
                l_content->flow_codecs = DAP_NEW_Z_SIZE(char *, sizeof(char*) * l_content->flows_count);
            }else{
                log_it(L_WARNING, "Corrupted flows string");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_INFO_CORRUPTED , "CLUSTER_PKT_CONTENT_FLOWS_STRING_CORRUPTED");
                return -102;
            }
        }break;

        case AVRS_CH_PKT_CLUSTER_ARG_CONTENT_FLOW_CODEC: {
            avrs_ch_pkt_tsd_flow_t * l_tsd_flow = (avrs_ch_pkt_tsd_flow_t *) a_tsd->data;
            if(a_tsd->size < sizeof(*l_tsd_flow)){
                log_it(L_WARNING, "Too small TSD flow packet %u bytes when minimum %zd", a_tsd->size, sizeof (*l_tsd_flow));
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_INFO_CORRUPTED , "CLUSTER_PKT_CONTENT_FLOW_TSD_TOO_SMALL");
                return -103;
            }
            if(l_tsd_flow->id < l_content->flows_count){
                log_it(L_WARNING, "Flow number %u is too big (should be not bigger than %zd)", l_tsd_flow->id, l_content->flows_count);
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_INFO_CORRUPTED , "CLUSTER_PKT_CONTENT_FLOW_ID_TOO_BIG");
                return -104;
            }
            size_t l_tsd_flow_data_size = a_tsd->size - sizeof(*l_tsd_flow);
            if( l_tsd_flow_data_size){
                if ( l_tsd_flow->data[l_tsd_flow_data_size-1] != '\0' ){// Its not null-terminated string!
                    log_it (L_WARNING, "TSD flow data is not null-terminated string when expected to be");
                    avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_INFO_CORRUPTED , "CLUSTER_PKT_CONTENT_FLOW_CODEC_NOT_NULL_TERMINATED");
                    return -105;
                }
                l_content->flow_codecs[l_tsd_flow->id] = dap_strdup( (char *) l_tsd_flow->data );
            }else{
                DAP_DEL_Z(l_content->flow_codecs[l_tsd_flow->id]);
            }
        } break;

        default: return -EINVAL; // Code of unknown TSD type
    }
    return 0;
}

/**
 * @brief s_parse_cluster_pkt_and_verify
 * @param a_avrs_ch
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_member_id
 * @param a_guuid
 * @param a_is_guuid
 * @param a_parse_callback
 * @param a_arg
 * @return
 */
static inline int s_parse_cluster_pkt_and_verify(avrs_ch_t *a_avrs_ch, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                 dap_hash_fast_t * a_member_id,
                                                 dap_guuid_t * a_guuid, bool * a_is_guuid,
                                                tsd_parse_callback_t a_parse_callback, void * a_arg)
{
    dap_tsd_t * l_tsd = NULL;
    bool l_sign_correct = false;
    bool l_is_guuid = false;
    dap_guuid_t l_guuid = {0};
    int l_ret = 0;

    for( size_t l_tsd_offset = 0; l_tsd_offset <a_pkt_args_size ; l_tsd_offset += dap_tsd_size(l_tsd) ){
        l_tsd = (dap_tsd_t *) (a_pkt->args + l_tsd_offset);
        if ( !dap_tsd_size_check (l_tsd, l_tsd_offset, a_pkt_args_size) ){
            log_it(L_WARNING, "Too big TSD size, %u when left only %zd in packet", l_tsd->size, a_pkt_args_size - l_tsd_offset);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CLUSTER_WRONG_REQUEST , "CLUSTER_PKT_TSD_SIZE_TOO_BIG");
            return -100;
        }
        switch(l_tsd->type){
            case AVRS_CH_PKT_CLUSTER_ARG_ID:
                l_guuid = dap_tsd_get_scalar(l_tsd, dap_guuid_t);
                l_is_guuid = true;
            break;

            case AVRS_CH_PKT_CLUSTER_ARG_SIGN:{
                if( avrs_ch_tsd_sign_pkt_verify(a_avrs_ch, l_tsd, l_tsd_offset, a_pkt, sizeof(*a_pkt), a_pkt_args_size) ){
                    if(a_member_id){
                        dap_hash_fast_t l_sign_hash = {};
                        dap_sign_get_pkey_hash((dap_sign_t*) l_tsd->data ,a_member_id);
                    }
                    l_sign_correct = true;
                }else{
                    l_ret = -1;
                    avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT , "CLUSTER_PKT_SIGN_INCORRECT");
                    goto lb_ret;
                }
            }break;
            default:
                if(a_parse_callback){

                    int l_parse_ret = a_parse_callback(a_avrs_ch, l_tsd, l_tsd_offset, a_pkt, a_pkt_args_size, l_guuid, l_is_guuid, a_arg) ;
                    if( l_parse_ret == 1){ // Just unknown packet
                        log_it(L_WARNING, "Unknown cluster packet arg id 0x%04hu", l_tsd->type);
                    }else if (l_parse_ret < 0){ // Smth wrong
                        l_ret = l_parse_ret;
                        goto lb_ret;
                    }
                }
        }
        if(l_sign_correct) // Sign must be last argument
            break;
    }
lb_ret:
    if(a_guuid)
        *a_guuid = l_guuid;
    if(a_is_guuid)
        *a_is_guuid = l_is_guuid;
    return l_ret;
}

/**
 * @brief The member_id_and_verify_sign_args struct
 */
struct member_id_and_verify_sign_args
{
    tsd_parse_member_id_and_check_sign_callback_t callback;
    avrs_cluster_t * cluster;
    avrs_cluster_member_t * member;
    dap_hash_fast_t member_id;
    void * arg;
};

/**
 * @brief s_get_member_id_and_verify_sign_callback_wrapper
 * @param a_avrs_ch
 * @param l_tsd
 * @param l_tsd_offset
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_guuid
 * @param a_is_guuid
 * @param a_arg
 * @return
 */
int s_get_member_id_and_verify_sign_callback_wrapper(avrs_ch_t *a_avrs_ch,dap_tsd_t* l_tsd, size_t l_tsd_offset,avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size, dap_guuid_t a_guuid, bool a_is_guuid, void * a_arg)
{
    struct member_id_and_verify_sign_args * l_args = (struct member_id_and_verify_sign_args*) a_arg;
    if( !a_is_guuid ){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CLUSTER_WRONG_REQUEST, "GUUID_NOT_PRESENT");
        return -5;
    }

    if(! l_args->cluster){
        l_args->cluster = avrs_cluster_find(a_guuid);
        if ( ! l_args->cluster ){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CLUSTER_NOT_FOUND, "GUUID_NOT_FOUND");
                return -6;
        }
    }
    return l_args->callback ? l_args->callback( a_avrs_ch, l_tsd, l_args->cluster, &l_args->member_id, l_args->arg) : 0;
}

/**
 * @brief s_parse_cluster_pkt_get_member_id_and_verify_sign
 * @param a_avrs_ch
 * @param a_cluster
 * @param a_member_id
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_parse_callback
 * @param a_arg
 * @return
 */
static inline int s_parse_cluster_pkt_get_member_id_and_verify_sign(avrs_ch_t *a_avrs_ch,avrs_cluster_t ** a_cluster, dap_hash_fast_t * a_member_id, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                                    tsd_parse_member_id_and_check_sign_callback_t a_parse_callback, void * a_arg)
{
    dap_guuid_t l_guuid={0};
    bool l_is_guuid = false;
    struct member_id_and_verify_sign_args l_args = { .callback = a_parse_callback, .arg = a_arg };
    int l_parse_ret = s_parse_cluster_pkt_and_verify(a_avrs_ch, a_pkt, a_pkt_args_size, a_member_id,&l_guuid,&l_is_guuid,
                                                     s_get_member_id_and_verify_sign_callback_wrapper, &l_args);
    if(l_parse_ret != 0){
        return l_parse_ret;
    }

    // Packet wasn't signed so no member_id was extracted
    if( dap_hash_fast_is_blank(&l_args.member_id ) ){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_NOT_PRESENT, "SIGN_NOT_PRESENT");
        return -7;
    }

    if( a_cluster)
        *a_cluster = l_args.cluster;
    if ( a_member_id )
        *a_member_id = l_args.member_id;

    return 0;
}

/**
 * @brief s_get_cluster_from_pkt_and_verify_sign
 * @param a_avrs_ch
 * @param a_pkt
 * @param a_pkt_args_size
 * @return
 */
static inline avrs_cluster_t * s_parse_cluster_pkt_and_verify_owner(avrs_ch_t *a_avrs_ch, avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,tsd_parse_member_id_and_check_sign_callback_t a_parse_callback, void * a_arg)
{
    dap_hash_fast_t l_id={};
    avrs_cluster_t * l_ret = NULL;
    if ( s_parse_cluster_pkt_get_member_id_and_verify_sign(a_avrs_ch,&l_ret, &l_id,a_pkt, a_pkt_args_size, a_parse_callback, a_arg)!= 0){
        return NULL;
    }
    if(l_ret && !dap_hash_fast_compare(&l_id, &l_ret->options.owner_id) ){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_ALIEN, "CLUSTER_PKT_SIGN_ALIEN");
        return NULL;
    }
    return l_ret;
}


/**
 * @brief The tsd_parse_callback_wrap struct
 */
struct callback_parse_member_args{
    tsd_parse_member_and_check_callback_t callback;
    void * arg;
    bool pass_if_itself;
    avrs_role_t roles;

    dap_hash_fast_t member_id;
    avrs_cluster_member_t * member;

    dap_hash_fast_t member_to_id;
    avrs_cluster_member_t * member_to;
};
/**
 * @brief s_parse_cluster_pkt_get_member_and_check_callback_wrap
 * @param a_avrs_ch
 * @param l_tsd
 * @param l_tsd_offset
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_guuid
 * @param a_is_guuid
 * @param a_arg
 * @return
 */
static int s_parse_cluster_pkt_get_member_and_check_callback_wrap(avrs_ch_t *a_avrs_ch, dap_tsd_t* l_tsd, avrs_cluster_t * a_cluster,  dap_hash_fast_t * a_member_id, void * a_arg)
{
    assert(a_arg);
    struct callback_parse_member_args * l_args=(struct callback_parse_member_args *) a_arg;

    // Check for member
    if (! l_args->member){
        l_args->member=  avrs_cluster_member_find(a_cluster, a_member_id);
        if(!l_args->member){
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_MEMBER_NOT_FOUND, "CLUSTER_MEMBER_OP_APPROVE_NOT_FOUND");
            return -12;
        }
        l_args->member_to = l_args->member;
        l_args->member_to_id = l_args->member->id; // may be a useless but why not? lets optimize some time after
    }

    switch(l_tsd->type){
        case AVRS_CH_PKT_CLUSTER_ARG_MEMBER:
            if(l_tsd->size != sizeof(dap_hash_fast_t)){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_ARG_INCORRECT, "CLUSTER_MEMBER_ARG_WRONG_SIZE");
                log_it (L_WARNING, "TSD section with member id is wrong size, %zd expected but %u received",
                        sizeof(dap_hash_fast_t), l_tsd->size );
                return -13;
            }
            memcpy(&l_args->member_to_id, l_tsd->data, sizeof(l_args->member_to_id));
            l_args->member_to = avrs_cluster_member_find( a_cluster, & l_args->member_to_id); // If not found - nothing bad, may be its in another table
        break;
        default:
            return l_args->callback ? l_args->callback(a_avrs_ch, l_tsd, a_cluster, l_args->member, l_args->member_to, &l_args->member_to_id, l_args->arg)
                                     : 1; // Code of unknown TSD type
    }
    return 0;

}

/**
 * @brief s_parse_cluster_pkt_get_member_and_check
 * @param a_avrs_ch
 * @param a_cluster
 * @param a_member
 * @param a_roles
 * @param a_pass_if_himself
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_parse_callback
 * @param a_arg
 * @return
 */
static inline int s_parse_cluster_pkt_get_member_and_check(avrs_ch_t *a_avrs_ch, avrs_cluster_t ** a_cluster, avrs_cluster_member_t **a_member_op, avrs_cluster_member_t **a_member_to,dap_hash_fast_t * a_member_to_id,avrs_role_t a_roles, bool a_pass_if_itself,
                                                           avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                                    tsd_parse_member_and_check_callback_t a_parse_callback, void * a_arg)
{
    dap_hash_fast_t l_member_op_id={};
    struct callback_parse_member_args l_args = {
        .callback = a_parse_callback,
        .arg = a_arg,
        .pass_if_itself = a_pass_if_itself,
        .roles = a_roles,
    };
    avrs_cluster_t *l_cluster = NULL;

    int l_parse_ret = s_parse_cluster_pkt_get_member_id_and_verify_sign(a_avrs_ch,&l_cluster, &l_member_op_id, a_pkt, a_pkt_args_size, s_parse_cluster_pkt_get_member_and_check_callback_wrap, &l_args);
    if(l_parse_ret != 0) {
        return l_parse_ret;
    }
    // Now check for permissions
    bool l_is_passed =
         ( dap_hash_fast_compare(&l_args.member_id, &l_cluster->options.owner_id)        || // If its owner
         ( l_args.pass_if_itself && dap_hash_fast_compare(&l_args.member_id, &l_args.member_to_id) ) || // If permitted to do with itself
         ( l_args.member->role & l_args.roles) );                                                   // If role is permitted

    if(!l_is_passed){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_MEMBER_SECURITY_ISSUE, "CLUSTER_MEMBER_SECUIRTY_ISSUE");
        return -666;
    }


    if(a_cluster)
        *a_cluster = l_cluster;
    if(a_member_op)
        *a_member_op = l_args.member;
    if(a_member_to)
        *a_member_to = l_args.member_to;
    if(a_member_to_id)
        *a_member_to_id = l_args.member_to_id;

    return 0;
}

/**
 * @brief The callback_parse_content_args struct
 */
struct callback_parse_content_args{
    tsd_parse_member_content_and_check_callback_t callback;
    void * arg;
    dap_guuid_t content_id;
    avrs_content_t * content;
};

/**
 * @brief s_parse_cluster_pkt_get_member_content_route_and_check_callback
 * @param a_avrs_ch
 * @param a_tsd
 * @param a_cluster
 * @param a_member
 * @param a_member_to
 * @param a_member_to_id
 * @param a_arg
 * @return
 */
static int s_parse_cluster_pkt_get_member_content_check_callback(avrs_ch_t *a_avrs_ch,dap_tsd_t* a_tsd, avrs_cluster_t * a_cluster, avrs_cluster_member_t * a_member, avrs_cluster_member_t * a_member_to, dap_hash_fast_t * a_member_to_id, void * a_arg)
{
    assert(a_arg);
    struct callback_parse_content_args * l_args=(struct callback_parse_content_args *) a_arg;
    switch(a_tsd->type){
        case AVRS_CH_PKT_CLUSTER_ARG_CONTENT_ID :
            if(a_tsd->size != sizeof(dap_guuid_t)){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_ARG_INCORRECT, "CLUSTER_ID_ARG_WRONG_SIZE");
                log_it (L_WARNING, "TSD section with content id is wrong size, %zd expected but %u received",
                        sizeof(dap_guuid_t), a_tsd->size );
                return -13;
            }
            l_args->content_id = dap_tsd_get_scalar(a_tsd,dap_guuid_t);
            l_args->content = avrs_cluster_content_find( a_cluster, &l_args->content_id);
            if(! l_args->content){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_NOT_FOUND, "CLUSTER_CONTENT_NOT_FOUND");
                return -20;
            }

        break;
        default:
            return l_args->callback ? l_args->callback(a_avrs_ch,a_tsd, a_cluster, a_member, a_member_to,a_member_to_id,
                                                       l_args->content, l_args->content_id,l_args->arg)
                                     : 1; // Code of unknown TSD type
    }
    return 0;

}
/**
 * @brief s_parse_cluster_pkt_get_member_content_route_and_check
 * @param a_avrs_ch
 * @param a_cluster
 * @param a_member_op
 * @param a_content
 * @param a_roles
 * @param a_pass_if_itself
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_parse_callback
 * @param a_arg
 * @return
 */
static inline int s_parse_cluster_pkt_get_member_content_check(avrs_ch_t *a_avrs_ch, avrs_cluster_t ** a_cluster, avrs_cluster_member_t **a_member_op, avrs_content_t **a_content,avrs_role_t a_roles,
                                                               bool a_pass_if_itself,
                                                           avrs_ch_pkt_cluster_t * a_pkt, size_t a_pkt_args_size,
                                                                    tsd_parse_member_content_and_check_callback_t a_parse_callback, void * a_arg)
{
    struct callback_parse_content_args l_args={
        .callback = a_parse_callback,
        .arg = a_arg
    };
    avrs_cluster_t *l_cluster = NULL;
    avrs_cluster_member_t *l_member_op = NULL;
    int l_parse_ret =  s_parse_cluster_pkt_get_member_and_check(a_avrs_ch,&l_cluster, &l_member_op, NULL,NULL, a_roles, a_pass_if_itself,
                                                                a_pkt, a_pkt_args_size,
                                                                s_parse_cluster_pkt_get_member_content_check_callback, &l_args);
    if(l_parse_ret != 0) {
        return l_parse_ret;
    }
    assert(l_cluster);
    assert(l_member_op);

    avrs_content_t * l_content = l_args.content;

    if( a_cluster ) *a_cluster = l_cluster;
    if( a_member_op ) *a_member_op = l_member_op;
    if( a_content ) *a_content = l_content;


    return 0;
}


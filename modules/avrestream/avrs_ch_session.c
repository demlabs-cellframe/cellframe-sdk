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
#include <dap_common.h>
#include <dap_tsd.h>
#include <stdint.h>

#include "avrs.h"
#include "avrs_ch.h"
#include "avrs_ch_pkt.h"
#include "avrs_ch_session.h"
#include "avrs_cluster.h"
#include "avrs_session.h"
#include "dap_hash.h"

#define LOG_TAG "avrs_ch_session"

// Session callbacks
#define     DAP_AVRS$SZ_SESSION_CB    512
static avrs_ch_pkt_session_callback_t s_pkt_in_session_callbacks[DAP_AVRS$SZ_SESSION_CB];
static size_t s_pkt_in_session_callbacks_size = 0;

typedef int (*tsd_parse_callback_t)(avrs_ch_t *a_avrs_ch,dap_tsd_t* l_tsd, size_t l_tsd_offset,avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size, void * a_arg);
struct content_req
{
    avrs_cluster_t * cluster;
    avrs_content_t * content;
    uint32_t session_content_flags;
};


static inline int s_parse_session_and_verify(avrs_ch_t *a_avrs_ch, avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size,
                                             dap_hash_fast_t * a_session_id, tsd_parse_callback_t a_parse_callback, void * a_arg);

static int s_parse_callback_content_add(avrs_ch_t *a_avrs_ch,dap_tsd_t* l_tsd, size_t l_tsd_offset,avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size, void * a_arg);
static int s_parse_callback_content_remove(avrs_ch_t *a_avrs_ch,dap_tsd_t* l_tsd, size_t l_tsd_offset,avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size, void * a_arg);
/**
 * @brief avrs_ch_pkt_in_session_add_callback
 * @param a_callback
 */
int avrs_ch_pkt_in_session_add_callback(avrs_ch_pkt_session_callback_t a_callback)
{
    if ( !(s_pkt_in_session_callbacks_size < DAP_AVRS$SZ_SESSION_CB) )
        return  log_it(L_ERROR, "Table of content call back is full (%ld entries), cb:%p cannot be added", s_pkt_in_session_callbacks_size, a_callback),
                -ENOMEM;

    debug_if(g_avrs_debug_more, L_DEBUG, "Added content call back:%p, index #%zd", a_callback, s_pkt_in_session_callbacks_size);

    s_pkt_in_session_callbacks[s_pkt_in_session_callbacks_size++] = a_callback;

    return  0;
}

/**
 * @brief avrs_ch_pkt_in_session
 * @param a_avrs_ch
 * @param a_pkt
 * @param a_pkt_args_size
 */
void avrs_ch_pkt_in_session(avrs_ch_t * a_avrs_ch, avrs_ch_pkt_session_t * a_pkt, size_t a_pkt_args_size)
{

    /// Only session op request thats could be passed without opened session
    if(a_pkt->type == AVRS_CH_PKT_SESSION_TYPE_OPEN){
        if (a_avrs_ch->session){  // Already opened
            log_it(L_WARNING, "[avrs_ch:%p] Session is already opened, close it first", a_avrs_ch);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_ALREADY_OPENED , "SESSION_ERROR_ALREADY_OPENED");
            return;
        }

        dap_hash_fast_t l_session_id ={};
        if (s_parse_session_and_verify(a_avrs_ch, a_pkt, a_pkt_args_size, &l_session_id, NULL, NULL) != 0 ){
            log_it(L_WARNING, "[avrs_ch:%p] Wrong session open request", a_avrs_ch);
            return;
        }
        // Create the new one or find existent session
        a_avrs_ch->session = avrs_session_open(a_avrs_ch, &l_session_id);
        return;
    }

    avrs_session_t *l_session = a_avrs_ch->session;

    // Everything else requires already opened session
    if(!a_avrs_ch->session){
        log_it(L_WARNING, "Session is not opened, open it first");
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_NOT_OPENED , "SESSION_NOT_OPENED");
        return;
    }

    switch(a_pkt->type){
        case AVRS_CH_PKT_SESSION_TYPE_UPDATE:{
        } break;
        case AVRS_CH_PKT_SESSION_TYPE_CLOSE:{
            avrs_session_delete(l_session);
            a_avrs_ch->session = NULL;
        } break;
        case AVRS_CH_PKT_SESSION_TYPE_CONTENT_ADD:{
            if( l_session->content_size == l_session->content_size_max ){
                log_it(L_WARNING, "We reached maximum size %u of contents for session",  l_session->content_size_max );
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_CONTENT_ID_WRONG , "SESSION_CONTENT_MAXIMUM");
                break;
            }


            struct content_req l_content_req = {};
            if (s_parse_session_and_verify(a_avrs_ch, a_pkt, a_pkt_args_size, NULL, s_parse_callback_content_add, &l_content_req) != 0 ){
                log_it(L_WARNING, "Content add request was wrong");
                break;
            }
            avrs_content_t * l_content = l_content_req.content;
            assert(l_content);
            uint32_t l_content_session_id = l_session->content_size;

            // If its for streaming out to the remote client we add this session to the streaming list
            if( l_content_req.session_content_flags & AVRS_SESSION_CONTENT_FLAG_STREAMING_OUT){
                int l_retval;
                // Caution! It could be blocking call. TODO replace with async version of this function
                if(l_retval = avrs_content_add_session_out( l_content,l_content_session_id, l_session), l_retval != 0){
                    log_it(L_WARNING, "Can't add content to the session, code %d", l_retval);
                    break;
                }
            }

            // If success we add content to the session's content list
            l_session->content[l_session->content_size].content = l_content;
            l_session->content_size++;
            if ( l_session->content_size_max == l_session->content_size){
                if( l_session->content_size < UINT32_MAX - 0xff ){
                    l_session->content_size_max += 0xff;
                    l_session->content = DAP_REALLOC(l_session->content, sizeof(avrs_content_t*) * l_session->content_size_max);
                }
            }
            char l_content_id_str[48] = {0};


            snprintf(l_content_id_str, sizeof(l_content_id_str) - 1, "%u", l_content_session_id);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_SUCCESS , l_content_id_str);

        } break;

        case AVRS_CH_PKT_SESSION_TYPE_CONTENT_REMOVE:{
            uint32_t l_content_id = UINT32_MAX;
            if (s_parse_session_and_verify(a_avrs_ch, a_pkt, a_pkt_args_size, NULL, s_parse_callback_content_remove, &l_content_id) != 0 ){
                log_it(L_WARNING, "Content remove request was wrong");
                break;
            }

            if(l_content_id > l_session->content_size){
                log_it(L_WARNING, "Content id too big");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_CONTENT_ID_WRONG , "SESSION_CONTENT_ID_TOO_BIG");
                break;
            }

            avrs_content_t * l_content = l_session->content[l_content_id].content;
            if(!l_content){
                log_it(L_WARNING, "Content already removed");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_CONTENT_ID_WRONG , "SESSION_CONTENT_ID_ALREADY_REMOVED");
                break;
            }

            l_session->content[l_content_id].content = NULL;

            // If it was last just reduce the array top
            if(l_content_id + 1 == l_session->content_size )
                l_session->content_size--;

            // TODO compress content array or add any other optimization

        } break;

        case AVRS_CH_PKT_SESSION_TYPE_CONTENT_UPDATE:
        case AVRS_CH_PKT_SESSION_TYPE_CLUSTER_ADD:
        case AVRS_CH_PKT_SESSION_TYPE_CLUSTER_DEL:
        case AVRS_CH_PKT_SESSION_TYPE_CLUSTER_UPDATE:
        default:
            log_it(L_ERROR, "[avrs_ch:%p] Unhandled AVRS Packet type: %d(%#x)", a_avrs_ch, a_pkt->type, a_pkt);

    }

    for(size_t i = 0; i < s_pkt_in_session_callbacks_size; i++)
        s_pkt_in_session_callbacks[i] (a_avrs_ch, l_session, a_pkt, a_pkt_args_size);
}

/**
 * @brief s_parse_callback_content_add
 * @param a_avrs_ch
 * @param l_tsd
 * @param l_tsd_offset
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_arg
 * @return
 */
static int s_parse_callback_content_add (
                        avrs_ch_t   *a_avrs_ch,
                        dap_tsd_t   *l_tsd,
                        size_t      l_tsd_offset,
            avrs_ch_pkt_session_t   *a_pkt,
                            size_t  a_pkt_args_size,
                            void    *a_arg
                                    )
{
    assert(a_arg);

    struct content_req *l_content_req = (struct content_req *) a_arg;

    switch(l_tsd->type)
    {
        case AVRS_CH_PKT_SESSION_ARG_CLUSTER_UUID:
            if ( !(l_content_req->cluster = avrs_cluster_find( dap_tsd_get_scalar(l_tsd, dap_guuid_t) )) )
            {
                log_it(L_WARNING, "[avrs_ch:%p] Can't find cluster UUID", a_avrs_ch);
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CLUSTER_NOT_FOUND , "SESSION_CLUSTER_ID_NOT_FOUND");
                return -2;
            }
        break;

        case AVRS_CH_PKT_SESSION_ARG_CONTENT_UUID:
            if(!l_content_req->cluster){
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_CONTENT_ID_WRONG , "SESSION_CONTENT_ID_SHOULD_BE_PREPENDED_WITH_CLUSTER_ID");
                log_it(L_WARNING, "Cluster ID should prepend content UUID");
                return -3;
            }

            l_content_req->content = avrs_cluster_content_find( l_content_req->cluster, (dap_guuid_t *) l_tsd->data );

            if( ! l_content_req->content){
                log_it(L_WARNING, "Can't find content id");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_NOT_FOUND , "SESSION_CONTENT_ID_NOT_FOUND");
                return -4;
            }

        break;

        case AVRS_CH_PKT_SESSION_ARG_CONTENT_FLAGS:
            if ( l_tsd->size != sizeof(l_content_req->session_content_flags) )
            {
                log_it(L_WARNING, "Wrong size, expecting %zd but got %u",sizeof(l_content_req->session_content_flags),
                       l_tsd->size);
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_ARG_INCORRECT , "TSD_SIZE_WRONG");
                return -4;
            }

            l_content_req->session_content_flags = dap_tsd_get_scalar(l_tsd, typeof(l_content_req->session_content_flags));
        break;

        default: return 1; // Code of unknown TSD type
    }

    return 0;
}

/**
 * @brief s_parse_callback_content_del
 * @param a_avrs_ch
 * @param l_tsd
 * @param l_tsd_offset
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_arg
 * @return
 */
static int s_parse_callback_content_remove (
                    avrs_ch_t   *a_avrs_ch,
                    dap_tsd_t   *l_tsd,
                    size_t      l_tsd_offset,
        avrs_ch_pkt_session_t   *a_pkt,
                    size_t      a_pkt_args_size,
                        void    *a_arg
                            )
{
uint32_t * l_content_id = (uint32_t *) a_arg;

    assert(l_content_id);

    switch(l_tsd->type)
    {
        case AVRS_CH_PKT_SESSION_ARG_CONTENT_ID:
            *l_content_id = dap_tsd_get_scalar(l_tsd, uint32_t);
            break;

        default: return 1; // Code of unknown TSD type
    }
    return 0;
}

/**
 * @brief s_parse_session_and_verify
 * @param a_avrs_ch
 * @param a_pkt
 * @param a_pkt_args_size
 * @param a_session_id
 * @param a_parse_callback
 * @param a_arg
 * @return
 */
static inline int s_parse_session_and_verify (
                            avrs_ch_t   *a_avrs_ch,
                avrs_ch_pkt_session_t   *a_pkt,
                            size_t      a_pkt_args_size,
                    dap_hash_fast_t     *a_session_id,
                tsd_parse_callback_t    a_parse_callback,
                                void    *a_arg
                                )
{
    dap_tsd_t * l_tsd = NULL;
    bool l_sign_correct = false;
    int l_ret = 0;

    for( size_t l_tsd_offset = 0; l_tsd_offset <a_pkt_args_size ; l_tsd_offset += dap_tsd_size(l_tsd) )
    {
        l_tsd = (dap_tsd_t *) (a_pkt->args + l_tsd_offset);

        if ( !dap_tsd_size_check (l_tsd, l_tsd_offset, a_pkt_args_size) )
        {
            log_it(L_WARNING, "Too big TSD size, %u when left only %zd in packet", l_tsd->size, a_pkt_args_size - l_tsd_offset);
            avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SESSION_WRONG_REQUEST , "SESSION_PKT_ERROR_TSD_SIZE_TOO_BIG");
            return -100;
        }

        switch(l_tsd->type)
        {
            case AVRS_CH_PKT_SESSION_ARG_SIGN:{
                if( avrs_ch_tsd_sign_pkt_verify(a_avrs_ch, l_tsd, l_tsd_offset, a_pkt, sizeof(*a_pkt), a_pkt_args_size) ){
                    if(a_session_id){
                        dap_hash_fast_t l_sign_hash = {};
                        dap_sign_get_pkey_hash((dap_sign_t*) l_tsd->data ,a_session_id);
                    }
                    l_sign_correct = true;
                }else{
                    l_ret = -1;
                    avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT , "SESSION_PKT_ERROR_SIGN_INCORRECT");
                    goto lb_ret;
                }
            }break;
            default:
                if(a_parse_callback){
                    int l_parse_ret = a_parse_callback(a_avrs_ch, l_tsd, l_tsd_offset, a_pkt, a_pkt_args_size, a_arg) ;
                    if( l_parse_ret == 1){ // Just unknown packet
                        log_it(L_WARNING, "Unknown session packet arg id 0x%04hu", l_tsd->type);
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
    return l_ret;
}

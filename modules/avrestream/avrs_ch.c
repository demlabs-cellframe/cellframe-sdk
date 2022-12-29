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

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_stream_ch_proc.h"

#include "avrs.h"
#include "avrs_cluster.h"
#include "avrs_session.h"
#include "avrs_content.h"
#include "avrs_ch_pkt.h"

#include "avrs_ch.h"
#include "avrs_ch_cluster.h"
#include "avrs_ch_session.h"
#include "dap_guiid.h"
#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_tsd.h"

#define LOG_TAG "avrs_ch"

typedef struct avrs_ch_pvt{
    byte_t padding[8];
} avrs_ch_pvt_t;

// Content callbacks
#define     DAP_AVRS$SZ_MAXCONTENT_CB   256
static avrs_ch_pkt_content_callback_t s_pkt_in_content_callbacks[DAP_AVRS$SZ_MAXCONTENT_CB];
static size_t s_pkt_in_content_callbacks_size = 0;


#define PVT(a) ((avrs_ch_pvt_t*)(a->_pvt))

static void s_ch_callback_new(dap_stream_ch_t * a_ch, void * a_arg);
static void s_ch_callback_delete(dap_stream_ch_t * a_ch, void * a_arg);
static void s_ch_callback_pkt_in(dap_stream_ch_t * a_ch, void * a_arg);
static void s_ch_callback_pkt_out(dap_stream_ch_t * a_ch, void * a_arg);

static inline void s_pkt_in_content(avrs_ch_t * a_avrs_ch, avrs_ch_pkt_content_t * a_pkt, size_t a_pkt_data_size);
static inline void s_pkt_in_retcode(avrs_ch_t * a_avrs_ch, int32_t a_code, const char * a_text);


/**
 * @brief avrs_ch_init
 * @return
 */
int avrs_ch_init(void)
{
    dap_stream_ch_proc_add(DAP_AVRS$K_CH_SIGNAL, s_ch_callback_new, s_ch_callback_delete, s_ch_callback_pkt_in, NULL);
    return 0;
}

/**
 * @brief avrs_ch_deinit
 */
void avrs_ch_deinit(void)
{

}

/**
 * @brief avrs_ch_pkt_in_content_add_callback
 * @param a_callback
 */
int avrs_ch_pkt_in_content_add_callback(avrs_ch_pkt_content_callback_t a_callback)
{
    if ( !(s_pkt_in_content_callbacks_size < DAP_AVRS$SZ_MAXCONTENT_CB) )
        return  log_it(L_ERROR, "Table of content call back is full (%ld entries), cb:%p cannot be added", s_pkt_in_content_callbacks_size, a_callback),
                -ENOMEM;

    debug_if(g_avrs_debug_more, L_DEBUG, "Added content call back:%p, index #%zd", a_callback, s_pkt_in_content_callbacks_size);

    s_pkt_in_content_callbacks[s_pkt_in_content_callbacks_size++] = a_callback;

    return  0;
}




/**
 * @brief s_ch_callback_new
 * @param a_ch
 * @param a_arg
 */
static void s_ch_callback_new(dap_stream_ch_t * a_ch, void * a_arg)
{
    avrs_ch_t * l_avrs_ch = DAP_NEW_Z_SIZE(avrs_ch_t, sizeof(avrs_ch_t) + sizeof(avrs_ch_pvt_t));

    assert(l_avrs_ch);

    debug_if(g_avrs_debug_more, L_DEBUG, "[stm_ch:%p] avrs_ch:%p --- is allocated", a_ch, l_avrs_ch);

    debug_if(g_avrs_debug_more, L_DEBUG, "[stm_ch:%p] avrs_ch:%p", a_ch, l_avrs_ch);

    a_ch->internal = l_avrs_ch;
}

/**
 * @brief s_ch_callback_delete
 * @param a_ch
 * @param a_arg
 */
static void s_ch_callback_delete(dap_stream_ch_t * a_ch, void * a_arg)
{
    avrs_ch_t * l_avrs_ch = AVRS_CH(a_ch);
    //avrs_ch_pvt_t * l_avrs_ch_pvt = PVT(l_avrs_ch);

    debug_if(g_avrs_debug_more, L_DEBUG, "[stm_ch:%p, avrs_ch:%p] avrs_ch_pvt:%p --- deallocated", a_ch, l_avrs_ch);
    DAP_FREE(l_avrs_ch);
}

/**
 * @brief s_ch_callback_pkt_in
 * @param a_ch
 * @param a_arg
 */
static void s_ch_callback_pkt_in(dap_stream_ch_t * a_ch, void * a_arg)
{
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    avrs_ch_t * l_avrs_ch = AVRS_CH(a_ch);

    if(l_ch_pkt){
        log_it(L_CRITICAL, "Received NULL packet in pkt_in callback");
        return;
    }


    switch (l_ch_pkt->hdr.type )
    {
        case DAP_AVRS$K_CH_CLUSTER:                                     // Cluster control packet
        {
            if(l_ch_pkt->hdr.size < sizeof(avrs_ch_pkt_cluster_t) ){
                log_it(L_WARNING, "Too small ch packet data size %u thats smaller then minimal cluster packet size %zd",
                       l_ch_pkt->hdr.size, sizeof(avrs_ch_pkt_cluster_t));
                break;
            }
            avrs_ch_pkt_cluster_t * l_pkt = (avrs_ch_pkt_cluster_t *) l_ch_pkt->data;
            size_t l_pkt_args_size = l_ch_pkt->hdr.size - sizeof(avrs_ch_pkt_cluster_t);
            avrs_ch_pkt_in_cluster(l_avrs_ch,l_pkt, l_pkt_args_size);
        }
        break;

        case DAP_AVRS$K_CH_SESSION:                                     // Session control packet
        {
            if(l_ch_pkt->hdr.size < sizeof(avrs_ch_pkt_session_t) ){
                log_it(L_WARNING, "Too small ch packet data size %u thats smaller then minimal session packet size %zd",
                       l_ch_pkt->hdr.size, sizeof(avrs_ch_pkt_session_t));
                break;
            }
            avrs_ch_pkt_session_t * l_pkt = (avrs_ch_pkt_session_t *) l_ch_pkt->data;
            size_t l_pkt_args_size = l_ch_pkt->hdr.size - sizeof(avrs_ch_pkt_session_t);
            avrs_ch_pkt_in_session(l_avrs_ch,l_pkt, l_pkt_args_size);
        }
        break;

        case DAP_AVRS$K_CH_CONTENT:                                     // Content packet
        {
            if(!l_avrs_ch->session ){                                   // No session, we do nothing
                debug_if( g_avrs_debug_more, L_WARNING, "Current stream channel connection has no active AVRS session");
                break;
            }

            if(l_ch_pkt->hdr.size < sizeof(avrs_ch_pkt_content_t) ) {
                log_it(L_WARNING, "Too small ch packet data size %u thats smaller then minimal content packet size %zd",
                       l_ch_pkt->hdr.size, sizeof(avrs_ch_pkt_content_t));
                break;
            }

            avrs_ch_pkt_content_t * l_pkt = (avrs_ch_pkt_content_t *) l_ch_pkt->data;
            size_t l_pkt_data_size = l_ch_pkt->hdr.size - sizeof(avrs_ch_pkt_content_t);
            s_pkt_in_content(l_avrs_ch, l_pkt, l_pkt_data_size);
        }
        break;

        case DAP_AVRS$K_CH_RETCODE:                                     // Ret code
        {
            if(l_ch_pkt->hdr.size < sizeof(avrs_ch_pkt_retcode_t) ) {
                log_it(L_WARNING, "Too small ch packet data size %u thats smaller then minimal retcode packet size %zd",
                       l_ch_pkt->hdr.size, sizeof(avrs_ch_pkt_retcode_t));
                break;
            }

            avrs_ch_pkt_retcode_t * l_pkt = (avrs_ch_pkt_retcode_t *) l_ch_pkt->data;
            size_t l_pkt_text_size = l_ch_pkt->hdr.size - sizeof(avrs_ch_pkt_retcode_t);

            if(l_pkt_text_size)
            {
                if(l_pkt->msg[l_pkt_text_size] != '\0' )
                {
                    log_it(L_WARNING, "Retcode %d has text that is not null terminated string", l_pkt->msgnum);
                    break;

                }

            s_pkt_in_retcode(l_avrs_ch, l_pkt->msgnum, l_pkt->msg);

            } else  s_pkt_in_retcode(l_avrs_ch, l_pkt->msgnum, "");
        }
        break;

        default:
            debug_if(g_avrs_debug_more, L_WARNING, "Unknown packet with subtype %c", l_ch_pkt->hdr.type);
    }
}

/**
 * @brief s_pkt_in_retcode
 * @param a_avrs_ch
 * @param a_pkt
 */
static inline void s_pkt_in_retcode(avrs_ch_t * a_avrs_ch, int32_t a_code, const char * a_text)
{
    switch(a_code){
        case 0: log_it(L_NOTICE, "Remote: success \"%s\" (code %d)", a_text, a_code);
        default: log_it(L_WARNING, "Remote: unknown error \"%s\"(code %d)", a_text, a_code);
    }
}




/**
 * @brief s_tsd_sign_pkt_verify
 * @param a_avrs_ch
 * @param a_tsd_sign
 * @param a_tsd_offset
 * @param a_pkt
 * @param a_pkt_hdr_size
 * @param a_pkt_args_size
 * @return
 */
bool avrs_ch_tsd_sign_pkt_verify(avrs_ch_t * a_avrs_ch, dap_tsd_t * a_tsd_sign, size_t a_tsd_offset, const void * a_pkt, size_t a_pkt_hdr_size, size_t a_pkt_args_size)
{
    dap_sign_t * l_pkt_sign = (dap_sign_t*) a_tsd_sign->data;

    if(a_tsd_sign->size +sizeof(*a_tsd_sign)> a_pkt_args_size - a_tsd_offset ){
        log_it(L_WARNING, "Corrupted TSD section SIGN in packet!");
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT, "PKT_ARG_SIGN_CORRUPTED");
        return false;
    }

    size_t l_pkt_sign_size_max = a_pkt_args_size - a_tsd_offset - sizeof(*a_tsd_sign);

    int l_ret;
    if( (l_ret = dap_sign_verify_all (l_pkt_sign,l_pkt_sign_size_max, a_pkt, a_pkt_hdr_size + a_tsd_offset ) ) != 0 )
    {
        switch(l_ret){
            case -3:
                log_it(L_WARNING, "TSD section is smaller than signature's header, possible corrupted!");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT, "PKT_TSD_TOO_SMALL");
                break;

            case -2:
                log_it(L_WARNING, "Sign has too big size fields inside, bigger than space left for sign!");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT, "PKT_ARG_SIGN_CORRUPTED");
            break;

            case -1:
                log_it(L_WARNING, "Packet doesn't pass signature verification, possible corrupted!");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT, "PKT_SIGN_DOESNT_PASS_VERIFICATION");
            break;

            default:
                log_it(L_WARNING, "Packet doesn't pass signature verification by unknown reaseon");
                avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_SIGN_INCORRECT, "PKT_SIGN_PROBLEM_UNKNOWN");
        }
        return false;
    }

    return true;
}

/**
 * @brief s_pkt_in_content
 * @param a_avrs_ch
 * @param a_pkt
 * @param a_pkt_data_size
 */
static inline void s_pkt_in_content(avrs_ch_t * a_avrs_ch, avrs_ch_pkt_content_t * a_pkt, size_t a_pkt_data_size)
{
    avrs_session_content_t * l_content_session = avrs_session_get_content(a_avrs_ch->session, a_pkt->content_id);
    if( !l_content_session){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_UNAVAILBLE, "NO_CONTENT_ID");
        return;
    }
    if(! (l_content_session->flags & AVRS_SESSION_CONTENT_FLAG_STREAMING_IN) ){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_UNAVAILBLE, "CONTENT_HAS_NO_FLAG_STREAMING_IN");
        return;
    }

    if ( avrs_session_content_in_data(a_avrs_ch->session, l_content_session, a_pkt->flow_id, a_pkt->data, a_pkt_data_size) != 0 ){
        avrs_ch_pkt_send_retcode_unsafe(a_avrs_ch->ch, AVRS_ERROR_CONTENT_CORRUPTED, "CONTENT_PACKET_CANT_BE_PROCESSED");
    }

    for(size_t i = 0; i < s_pkt_in_content_callbacks_size; i++)
        s_pkt_in_content_callbacks[i] (a_avrs_ch,l_content_session, a_pkt, a_pkt_data_size);
}



/**
 * @brief s_ch_callback_pkt_out
 * @param a_ch
 * @param a_arg
 */
static void s_ch_callback_pkt_out(dap_stream_ch_t * a_ch, void * a_arg)
{
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    avrs_ch_t * l_avrs_ch = AVRS_CH(a_ch);

    // Not sure how it can happens
    if(l_ch_pkt){
        log_it(L_CRITICAL, "Received NULL packet in pkt_in callback");
        return;
    }

    // Check if session is opened or not
    avrs_session_t * l_session = l_avrs_ch->session;
    if(! l_session){
        log_it(L_WARNING, "Session is not open, nothing to stream out");
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        return;
    }

    // Go through all session content
    for(uint32_t i = 0; i < l_session->content_size; i++ ){
        avrs_session_content_t * l_session_content = &l_session->content[i];
        if(!l_session_content->content  ||  ! (l_session_content->flags & AVRS_SESSION_CONTENT_FLAG_STREAMING_OUT )) // Was removed or its not streaming out
            continue;

        size_t l_pkt_data_size = avrs_session_content_out_data_size(l_session, l_session_content);
        avrs_ch_pkt_content_t *l_pkt = DAP_NEW_STACK_SIZE(avrs_ch_pkt_content_t, sizeof(avrs_ch_pkt_content_t)+ l_pkt_data_size);
        l_pkt->content_id = i;
        l_pkt->flow_id = avrs_session_content_out_pkt_type(l_session, l_session_content);
        l_pkt_data_size = avrs_session_content_out_data_copy(l_session, l_session_content, l_pkt->data);

        avrs_session_content_out_pkt_next(l_session, l_session_content);
    }
    avrs_session_content_out_postproc(l_session);
}

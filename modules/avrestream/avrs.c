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

    MODIFICATION HISTORY:

        29-DEC-2022 RRL Added a first set of routines are supposed to be used as an API for ConfCall frontend


*/

#include "dap_common.h"
#include "dap_tsd.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"

#include "avrs_ch_pkt.h"
#include "avrs_cluster.h"
#include "avrs.h"
#include "avrs_ch.h"


#define LOG_TAG "avrs"
int g_avrs_debug_more = 1;

static  dap_stream_ch_t *s_ch;


static void s_ch_new(dap_stream_ch_t * a_ch, void * a_arg)
{
avrs_ch_t *l_avrs_ch;

    if ( !(l_avrs_ch = DAP_NEW_Z_SIZE(avrs_ch_t, sizeof(avrs_ch_t))) )
         return log_it(L_ERROR, "Cannot allocate <avrs_ch_t> context, errno:%d", errno);


    debug_if(g_avrs_debug_more, L_DEBUG, "[stm_ch:%p] avrs_ch:%p --- is allocated", a_ch, l_avrs_ch);

    a_ch->internal = l_avrs_ch;
}

/**
 * @brief s_ch_callback_delete
 * @param a_ch
 * @param a_arg
 */
static void s_ch_delete(dap_stream_ch_t * a_ch, void * a_arg)
{
    avrs_ch_t * l_avrs_ch = AVRS_CH(a_ch);

    debug_if(g_avrs_debug_more, L_DEBUG, "[stm_ch:%p] avrs_ch:%p --- deallocated", a_ch, l_avrs_ch);
    DAP_FREE(l_avrs_ch);
    a_ch->internal = NULL;
}



/*
 *   DESCRIPTION: A routine is supposed to be called on received data block on the DAP_AVRS$K_CH_RETCODE channel
 *
 *   INPUTS:
 *      a_ch:   A channel context
 *      a_arg:  A packet to be processed
 *
 *   OUTPUTS:
 *      NONE
 *
 *   RETURNS:
 *      NONE
 */
static void    s_ch_packet_in (
                            dap_stream_ch_t *a_ch,
                                    void    *a_arg
                                        )
{
dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
avrs_ch_t   *l_avrs_ch = AVRS_CH(a_ch);
avrs_ch_pkt_retcode_t   *l_pkt_rc;

    if(l_ch_pkt)
        return  log_it(L_CRITICAL, "[ch:%p, avrs_ch:%p] Received NULL packet in pkt_in callback", a_ch, l_avrs_ch);

    switch (l_ch_pkt->hdr.type )
    {
        case DAP_AVRS$K_CH_RETCODE:                                     // Ret code
            l_pkt_rc = (avrs_ch_pkt_retcode_t *) l_ch_pkt->data;
            debug_if(g_avrs_debug_more, L_DEBUG, "Retcode: [msgnum:%d, len:%d, text:'%.*s'",
                     l_pkt_rc->msgnum, l_pkt_rc->msglen, l_pkt_rc->msglen, l_pkt_rc->msg);
        default:
            log_it (L_ERROR, "Unhandled/illegal packet with subtype %c", l_ch_pkt->hdr.type);
    }
}



static void    s_ch_packet_out (
                            dap_stream_ch_t *a_ch,
                                    void    *a_arg
                                        )
{
dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
avrs_ch_t   *l_avrs_ch = AVRS_CH(a_ch);
avrs_ch_pkt_retcode_t   *l_pkt_rc;

    return  log_it(L_INFO, "[ch:%p, avrs_ch:%p] --- called", a_ch, l_avrs_ch);
}





/*
 *   DESCRIPTION: initialize AVRS retcode channel
 *
 */
int dap_avrs_init   (dap_config_t * g_config)
{
    /*
     * void dap_stream_ch_proc_add(uint8_t id,
     *                      dap_stream_ch_callback_t new_callback,
     *                      dap_stream_ch_callback_t delete_callback,
                            dap_stream_ch_callback_t packet_in_callback,
                            dap_stream_ch_callback_t packet_out_callback);
     */
    dap_stream_ch_proc_add(DAP_AVRS$K_CH_RETCODE,
                           s_ch_new,
                           s_ch_delete,
                           s_ch_packet_in,
                           s_ch_packet_out);

    debug_if(g_avrs_debug_more, L_INFO, "Added processor for RETCODE channel");

    return 0;
}


int dap_avrs_deinit   (dap_config_t * g_config)
{

    return  0;
}

/*
 *   DESCRIPTION: A helper routine to create cluster with a given type
 *
 *   INPUTS:
 *      a_clu_type:     cluster type code
 *      a_clu_info:     Cluster information text string
 *
 *   OUTPUTS:
 *      a_clu_id:       An assigned Cluster Id
 *
 */
int         dap_avrs_create_cluster (
                                    int     a_clu_type,
                                    char    *a_clu_info,
                            dap_guuid_t     *a_clu_id
                                    )
{
int         l_rc;
dap_guuid_t l_cluster_guuid = {0};
size_t      l_args_sz;
char        l_args[512];

    /* Presets ... */
    l_args_sz = 0;
    l_cluster_guuid = dap_guuid_new ();

    /* Form a list of arguments for the request ... */
    l_args_sz = dap_tsd_put (AVRS_CH_PKT_CLUSTER_ARG_ID, &l_cluster_guuid, sizeof(dap_guuid_t), l_args, sizeof(l_args));
    if ( a_clu_info && (l_rc = strnlen(a_clu_info, AVRS_CLUSTER_MEMBER_INFO_STRING_SIZE_MAX)) )
    {
        l_args_sz += dap_tsd_put (AVRS_CH_PKT_CLUSTER_TYPE_INFO, a_clu_info, l_rc,
                              l_args + l_args_sz, sizeof(l_args) - l_args_sz);
    }

    /* Enqueue  request ... */
    l_rc = avrs_ch_pkt_send_cluster_unsafe(s_ch, AVRS_CH_PKT_CLUSTER_TYPE_CREATE, l_args, l_args_sz );

    *a_clu_id = l_cluster_guuid;

    return  0;
}


int     dap_avrs_add_member2cluster (
                        const   dap_guuid_t *l_cluster_guiid,
                                dap_ile2_t  *a_items
                                        )
{
int         l_rc;
size_t      l_args_sz;
char        l_args[2048];
dap_ile2_t  *l_item;

    /* Presets ... */
    l_args_sz = 0;

    /* Run over "NULLILE" terminated items list and encapsulate data into the TSDs */
    for (l_item = a_items; l_item->code && l_item->sz && l_item->data; l_item++)
    {
        switch ( l_item->code )
        {
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ROLE:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ADDR:

            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_DISPLAY_NAME:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_NAME:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SECOND_NAME:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SURNAME:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_PATRONIM:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_STATUS:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_TITLE:
            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SIGNAL:
                l_args_sz += dap_tsd_put (l_item->code, l_item->data, l_item->sz, l_args + l_args_sz, sizeof(l_args) - l_args_sz);

            case AVRS_CH_PKT_CLUSTER_ARG_MEMBER_AVATAR:
            default:
                log_it(L_WARNING, "Ingore unhandled/illegal Item code:%d(%#x), s:%d", l_item->code, l_item->code, l_item->sz );
        }
    }

    l_rc = avrs_ch_pkt_send_cluster_unsafe(s_ch, AVRS_CH_PKT_CLUSTER_TYPE_MEMBER_REQUEST_ADD, l_args, l_args_sz);

    return  0;
}




#if     1   /* Examples of using of AVRS routines */

dap_guuid_t     l_member;
avrs_role_t     l_role = AVRS_ROLE_ALL;
dap_chain_addr_t l_addr = {};
char    l_disp_name [] = {"Dr. SysMan"},
        l_name [] = {"Rus"},
        l_snd_name [] = {"La"},
        l_status [] = {"Swords & Sushi <---> KaZaki & Vodka"},
        l_title [] = {"BMF"}
        ;


static dap_ile2_t l_clu_member_items [] = {
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER, sizeof(dap_guuid_t), &l_member},
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ROLE, sizeof(avrs_role_t), &l_role},
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_ADDR, sizeof(dap_chain_addr_t), &l_addr},
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_DISPLAY_NAME, sizeof(l_disp_name), l_disp_name },
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_NAME, sizeof(l_name), l_name},
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_SECOND_NAME, sizeof(l_snd_name), l_snd_name},
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_STATUS, sizeof(l_status), l_status},
    {AVRS_CH_PKT_CLUSTER_ARG_MEMBER_TITLE, sizeof(l_title), l_title},

    ILENULL                                                             /* End-Of-List marker , mast be !!! */
};



extern  dap_config_t *g_config;
int avrs_dev_helpr_routine  (void)
{
int  l_rc;
dap_guuid_t l_cluster_guiid = {0};

    l_rc = dap_avrs_init   (g_config);

    l_rc = dap_avrs_create_cluster (CLUSTER_SETUP_MEETING, "For members & no-members only", &l_cluster_guiid);
    l_rc = dap_avrs_add_member2cluster (&l_cluster_guiid, l_clu_member_items);

    return l_rc;
}
#endif

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

#include <assert.h>
#include <pthread.h>
#include <glib.h>
#include <gst/gst.h>
#include <gst/app/app.h>
#include <gst/app/gstappsink.h>
#include <gst/app/gstappsrc.h>
#include <gst/gstbin.h>
#include <gst/gstbus.h>
#include <gst/gstcaps.h>
#include <gst/gstelement.h>
#include <gst/gstobject.h>
#include <gst/gstpipeline.h>
#include <uthash.h>

#include <dap_common.h>
#include <dap_list.h>
#include <dap_strfuncs.h>
#include <dap_context.h>
#include <dap_stream_worker.h>
#include <dap_worker.h>
#include <dap_events.h>

#include "avrs_ch.h"
#include "avrs_ch_pkt.h"
#include "avrs_session.h"
#include "avrs_content.h"
#include "dap_events_socket.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "gst/gstbuffer.h"
#include "gst/gstpad.h"
#include "gst/gstsample.h"

#define LOG_TAG "avrs_content"
enum content_gst_app { CONTENT_GST_APP_SINK, CONTENT_GST_APP_SRC};
struct content_gst{
    enum content_gst_app type;
    avrs_content_t * content;
    GstPipeline *pipe;
    GstElement *pipe_element;
    GstBus * bus;
    guint bus_watch_id;
    union{
        GstAppSrc **app_src; // NULL if not present, number same as flows number
        GstAppSink **app_sink;
    };
};

struct app_sink_args{
    struct content_gst * content_gst;
    size_t flow_id;
    char flow_char;
    GstAppSink * app_sink;
};

typedef struct avrs_content_pvt {
    struct content_gst in;
    struct content_gst out;
} avrs_content_pvt_t;

/**
 * @brief The avrs_hh struct
 */
struct avrs_ch_hh{
    dap_events_socket_t * es_input;
    dap_stream_ch_uuid_t ch_uuid;
    avrs_ch_t * avrs;
    UT_hash_handle hh;
};

#define PVT(a)  ((avrs_content_pvt_t*)  (a)->pvt )
#define DAP_CONTEXT_TYPE_AVRS_GST    1000


static GMainLoop *s_gst_loop = NULL;
static dap_context_t * s_context = NULL;
static GMainContext *s_context_gst = NULL;
static dap_events_socket_t * s_queue_app_sink = NULL;
static struct avrs_ch_hh * s_avrs_ch_hh = NULL;


static void s_gst_context_callback_started(dap_context_t * a_context,void * a_arg);
static void s_gst_context_callback_stopped(dap_context_t * a_context,void * a_arg);

static int s_connect_with_gstreamer(avrs_content_t * a_content, enum content_gst_app a_content_gst_type, struct content_gst * a_content_gst,  const char * a_gst_str );
static void s_gstreamer_deinit(avrs_content_t * a_content, struct content_gst * a_content_gst);

static gboolean s_pipeline_bus_call (GstBus *a_bus, GstMessage *a_msg, gpointer a_data);

static void s_app_sink_callback_destroy(gpointer a_user_data);
static void s_app_sink_callback_eos(GstAppSink *a_app_sink, gpointer a_user_data);
static GstFlowReturn s_app_sink_callback_new_preroll(GstAppSink *a_app_sink, gpointer a_user_data);
static GstFlowReturn s_app_sink_callback_new_sample(GstAppSink *a_app_sink, gpointer a_user_data);
static void s_app_sink_callback_queue_ptr(dap_events_socket_t * a_es, void * a_arg);
static void s_app_sink_callback_queue_ptr_iter(dap_worker_t * a_worker,void * a_arg);


/**
 * @brief avrs_content_init
 * @return
 */
int avrs_content_init()
{
    s_context = dap_context_new(DAP_CONTEXT_TYPE_AVRS_GST);
    dap_context_run(s_context,-1, DAP_CONTEXT_POLICY_DEFAULT, 0,
                    DAP_CONTEXT_FLAG_WAIT_FOR_STARTED | DAP_CONTEXT_FLAG_EXIT_IF_ERROR,
                    s_gst_context_callback_started, s_gst_context_callback_stopped, NULL);

    return 0;
}

/**
 * @brief s_gst_context_callback_started
 * @param a_context
 * @param a_arg
 */
static void s_gst_context_callback_started(dap_context_t * a_context,void * a_arg)
{
    int argc = 1;
    GError * l_gerr = NULL;
    s_context_gst = g_main_context_new ();
    g_main_context_push_thread_default(s_context_gst);

    // GStreamer init
    if( gst_init_check (NULL, NULL, & l_gerr) == FALSE ){
        if (l_gerr){
            log_it(L_CRITICAL, "GStreamer initialization error: \"%s\"", l_gerr->message);
            g_error_free (l_gerr);
        }
        return;
    }

    s_gst_loop = g_main_loop_new (s_context_gst, FALSE);
    g_main_loop_run(s_gst_loop);
    a_context->signal_exit = true;
}

/**
 * @brief s_gst_context_callback_stopped
 * @param a_context
 * @param a_arg
 */
static void s_gst_context_callback_stopped(dap_context_t * a_context,void * a_arg)
{

}

/**
 * @brief avrs_content_deinit
 */
void avrs_content_deinit()
{

}
/**
 * @brief avrs_content_new
 * @param a_flags
 * @param a_flows
 * @return
 */
avrs_content_t * avrs_content_new()
{
    avrs_content_t * l_ret = DAP_NEW_Z_SIZE(avrs_content_t, sizeof(avrs_content_t) + sizeof(avrs_content_pvt_t));
    assert(l_ret);

    pthread_rwlock_init(&l_ret->rwlock, NULL);

    PVT(l_ret)->in.content = l_ret;
    PVT(l_ret)->out.content = l_ret;

    debug_if(g_avrs_debug_more, L_DEBUG, "[avrs_cnt:%p] --- created", l_ret);

    return l_ret;
}

/**
 * @brief avrs_content_delete
 * @param a_content
 */
void avrs_content_delete(avrs_content_t * a_content)
{
    assert(a_content);
    if(a_content->cluster)
        avrs_cluster_content_remove(a_content);

    if(a_content->flows)
        DAP_DELETE(a_content->flows);
    if(a_content->flow_codecs)
        DAP_DELETE(a_content->flow_codecs);

    DAP_DELETE(a_content);
}

void avrs_content_set_flows(avrs_content_t * a_content, const char * a_flows)
{
    assert(a_flows);
    size_t l_flows_count = strlen(a_flows);
    assert(l_flows_count);

    if(a_content->flows_count){
        // Realloc codecs array
        a_content->flow_codecs = DAP_REALLOC(a_content->flow_codecs , sizeof(*a_content->flow_codecs)* l_flows_count);
        if(a_content->flows_count < l_flows_count){
            memset ( a_content->flow_codecs +a_content->flows_count,0, (l_flows_count - a_content->flows_count)
                     * sizeof(*a_content->flow_codecs) );
        }
        // Realloc for input (if present)
        if(PVT(a_content)->in.pipe ){
            PVT(a_content)->in.app_sink = DAP_REALLOC(PVT(a_content)->in.app_sink, sizeof(*PVT(a_content)->in.app_sink)
                                                      * l_flows_count);
            if(a_content->flows_count < l_flows_count)
                memset ( PVT(a_content)->in.app_sink +a_content->flows_count,0, (l_flows_count - a_content->flows_count)
                         * sizeof(*PVT(a_content)->in.app_sink) );

        }
        // Realloc for output (if present)
        if(PVT(a_content)->out.pipe ){
            PVT(a_content)->out.app_sink = DAP_REALLOC(PVT(a_content)->out.app_sink, sizeof(*PVT(a_content)->out.app_sink)
                                                      * l_flows_count);
            if(a_content->flows_count < l_flows_count)
                memset ( PVT(a_content)->out.app_sink +a_content->flows_count,0, (l_flows_count - a_content->flows_count)
                         * sizeof(*PVT(a_content)->out.app_sink) );

        }
    }else{
        a_content->flow_codecs = DAP_NEW_Z_SIZE(char*, sizeof(char*)* l_flows_count);
    }
    a_content->flows_count = l_flows_count;

}

/**
 * @brief s_pipeline_bus_call
 * @param bus
 * @param msg
 * @param data
 * @return
 */
static gboolean s_pipeline_bus_call (GstBus *a_bus, GstMessage *a_msg, gpointer a_data)
{
    struct content_gst * l_content_gst = (struct content_gst *) a_data;

    switch (GST_MESSAGE_TYPE (a_msg)) {
        case GST_MESSAGE_ERROR: {
            GError *l_err = NULL;
            gchar *l_debug = NULL;

            gst_message_parse_error (a_msg, &l_err, &l_debug);
            g_assert(l_err);
            log_it(L_ERROR, "GStreamer pipeline rrror: %s\n", l_err->message);
            g_error_free (l_err);
            if(l_debug)
                g_free (l_debug);

            gst_element_set_state ( l_content_gst->pipe_element , GST_STATE_READY);
          break;
        } break;

        case GST_MESSAGE_CLOCK_LOST:
            /* Get a new clock */
            gst_element_set_state ( l_content_gst->pipe_element, GST_STATE_PAUSED);
            gst_element_set_state ( l_content_gst->pipe_element, GST_STATE_PLAYING);
        break;

        default: break;
    }
    return TRUE;
}
/**
 * @brief s_connect_with_gstreamer
 * @param a_content
 * @param a_content_gst
 * @param a_gst_str
 * @return
 */
static int s_connect_with_gstreamer(avrs_content_t * a_content, enum content_gst_app a_content_gst_type, struct content_gst * a_content_gst,  const char * a_gst_str )
{
    GError * l_error = NULL;
    int l_errcode = 0;

    // Check if its already initialized
    if(a_content_gst->pipe){
        log_it(L_ERROR, "GST pipe is aready initialized ");
        l_errcode = -1;
        goto lb_err;
    }
    // Set type
    a_content_gst->type = a_content_gst_type;
    //  Init pipe
    a_content_gst->pipe_element =  gst_parse_launch(a_gst_str, &l_error);
    if(!a_content_gst->pipe){
        assert(l_error);
        log_it(L_ERROR, "Parse error: \"%s\" (code %d)", l_error->message, l_error->code);
        l_errcode = -2;
        goto lb_err;
    }
    a_content_gst->pipe = GST_PIPELINE (a_content_gst->pipe_element);

    // Set auto clocking
    gst_pipeline_auto_clock(a_content_gst->pipe);

    // Get bus
    a_content_gst->bus = gst_pipeline_get_bus ( a_content_gst->pipe );
    if(!a_content_gst->bus){
        log_it(L_ERROR, "Can't get bus from pipeline");
        l_errcode = -2;
        goto lb_err;
    }

    // Configure bus signals
    gst_bus_add_signal_watch (a_content_gst->bus);
    g_signal_connect (a_content_gst->bus, "message", G_CALLBACK (s_pipeline_bus_call), a_content_gst);


    switch(a_content_gst_type){
        case CONTENT_GST_APP_SINK:
            a_content_gst->app_sink = DAP_NEW_Z_SIZE( typeof(*a_content_gst->app_sink), sizeof(*a_content_gst->app_sink)
                                           *a_content->flows_count);
        break;
        case CONTENT_GST_APP_SRC:
                a_content_gst->app_src = DAP_NEW_Z_SIZE( typeof(*a_content_gst->app_src), sizeof(*a_content_gst->app_src)
                                               *a_content->flows_count);
        break;
        default: // Unexpectable
            assert(0);
            l_errcode = -10;
            goto lb_err;
    }

    // Parse sink/src
    for (size_t i = 0; i < a_content->flows_count; i++){
        char l_flow_str[16];

        //Try to compose flow element name
        if( snprintf(l_flow_str,sizeof(l_flow_str),"flow_%c", a_content->flows[i] ) <= 0) {
            log_it(L_ERROR, "Wrong flow character 0x%02X", a_content->flows[i] );
            l_errcode = -2;
            goto lb_err;
        }

        // Try to get element with specified name
        GstElement * l_app = gst_bin_get_by_name( GST_BIN(a_content_gst->pipe_element), l_flow_str);
        if( ! l_app ){
            log_it(L_ERROR, "No \"%s\" bin element in pipeline", l_flow_str);
            l_errcode = -3;
            goto lb_err;
        }

        switch(a_content_gst_type){
            case CONTENT_GST_APP_SINK:{ // Try to cast element as app_sink
                GstAppSink * l_app_sink = a_content_gst->app_sink[i] = GST_APP_SINK( l_app );
                if( !l_app_sink ){
                    log_it(L_ERROR, "%s is not \"app_sink\" element",l_flow_str);
                    l_errcode = -4;
                    goto lb_err;
                }
                GstAppSinkCallbacks l_app_sink_callbacks = {
                    .eos = s_app_sink_callback_eos,
                    .new_preroll = s_app_sink_callback_new_preroll,
                    .new_sample = s_app_sink_callback_new_sample
                };
                struct app_sink_args * l_app_sink_args = DAP_NEW_Z(struct app_sink_args);
                l_app_sink_args->app_sink = l_app_sink;
                l_app_sink_args->flow_id = i;
                l_app_sink_args->flow_char = a_content->flows[i];
                l_app_sink_args->content_gst = a_content_gst;
                gst_app_sink_set_callbacks(l_app_sink, &l_app_sink_callbacks, l_app_sink_args, s_app_sink_callback_destroy);
            }break;
            case CONTENT_GST_APP_SRC: // Try to cast element as app_src
                if( !(a_content_gst->app_src[i] = GST_APP_SRC( l_app ) ) ){
                    log_it(L_ERROR, "%s is not \"app_src\" element",l_flow_str);
                    l_errcode = -4;
                    goto lb_err;
                }
            break;
        }
    }

    return 0;
lb_err:
    s_gstreamer_deinit(a_content, a_content_gst);
    return l_errcode;
}

/**
 * @brief s_gstreamer_deinit
 * @param a_content
 * @param a_content_gst
 */
static void s_gstreamer_deinit(avrs_content_t * a_content, struct content_gst * a_content_gst)
{
    // Clear memory
    if(a_content_gst->bus){
        gst_object_unref(a_content_gst->bus);
        a_content_gst->bus = NULL;
    }

    if(a_content_gst->pipe){
        gst_element_set_state (a_content_gst->pipe_element, GST_STATE_NULL);
        gst_object_unref(a_content_gst->pipe);
        a_content_gst->pipe = NULL;
        a_content_gst->pipe_element = NULL;
    }

    switch(a_content_gst->type){
        case CONTENT_GST_APP_SINK:
            if (a_content_gst->app_sink){
                for(size_t i=0; i < a_content->flows_count; i++)
                    if(a_content_gst->app_sink[i])
                        gst_object_unref( a_content_gst->app_sink[i] );
                DAP_DELETE(a_content_gst->app_sink);
            }
        break;
        case CONTENT_GST_APP_SRC:
            if (a_content_gst->app_src){
                for(size_t i=0; i < a_content->flows_count; i++)
                    if(a_content_gst->app_src[i])
                        gst_object_unref( a_content_gst->app_src[i] );
                DAP_DELETE(a_content_gst->app_src);
            }
        break;
        default: assert(0);
    }

}

/**
 * @brief s_app_sink_callback_destroy
 * @param a_user_data
 */
static void s_app_sink_callback_destroy(gpointer a_user_data)
{
    DAP_DELETE(a_user_data);
}
/**
 * @brief s_app_sink_callback_eos
 * @param appsink
 * @param user_data
 */
static void s_app_sink_callback_eos(GstAppSink *a_app_sink, gpointer a_user_data)
{
    struct app_sink_args * l_app_sink_args = (struct app_sink_args *) a_user_data;
}

/**
 * @brief s_app_sink_callback_new_preroll
 * @param appsink
 * @param user_data
 * @return
 */
static GstFlowReturn s_app_sink_callback_new_preroll(GstAppSink *a_app_sink, gpointer a_user_data)
{
    struct app_sink_args * l_app_sink_args = (struct app_sink_args *) a_user_data;
    return GST_FLOW_OK;
}

/**
 * @brief s_app_sink_callback_new_sample
 * @param appsink
 * @param user_data
 * @return
 */
static GstFlowReturn s_app_sink_callback_new_sample(GstAppSink *a_app_sink, gpointer a_user_data)
{
    struct app_sink_args * l_app_sink_args = (struct app_sink_args *) a_user_data;
    GstSample * l_sample = gst_app_sink_pull_sample(a_app_sink);
    if( l_sample ){
        GstBuffer * l_buffer = gst_sample_get_buffer(l_sample);
        GstMapInfo l_mem_info ={};
        if(gst_buffer_map(l_buffer, &l_mem_info,0 )){
            avrs_content_data_push_sessions_out_mt (l_app_sink_args->content_gst->content, l_app_sink_args->flow_id,
                                       l_mem_info.data,l_mem_info.size );
            gst_buffer_unmap(l_buffer,&l_mem_info);
        }
        gst_buffer_unref(l_buffer);
        gst_sample_unref(l_sample);
        return GST_FLOW_OK;
    }else if (gst_app_sink_is_eos(a_app_sink)){
        log_it(L_NOTICE, "End-of-stream");
        return GST_FLOW_EOS;
    }else
        return GST_FLOW_CUSTOM_ERROR;
}


/**
 * @brief Connect content input and output data flows with GStreamer pipelines
 * @details GStreamer pipelines should be started from "app_src" item for out and ended with "app_sink" for input
 * @details For different flows app_src and app_sink items should be named with the same name as flows have with prefix
 * @details flow, like "flow_a", "flow_b", "flow_v", "flow_z" and etc
 * @param a_content
 * @param GStreamer pipeline for output data flows
 * @param GStreamer pipeline for input data flows
 * @return 0 if success
 */
int avrs_content_pipeline_connect(avrs_content_t * a_content, const char * a_gst_out, const char * a_gst_in)
{
    if(a_gst_out){
        int l_ret = s_connect_with_gstreamer(a_content, CONTENT_GST_APP_SRC, &PVT(a_content)->in, a_gst_out );
        if(l_ret)
            return l_ret;
    }
    if(a_gst_in){
        int l_ret = s_connect_with_gstreamer(a_content, CONTENT_GST_APP_SINK, &PVT(a_content)->out, a_gst_in );
        if(l_ret)
            return l_ret;
    }
    return 0;
}

/**
 * @brief avrs_content_flow_in_set_caps
 * @param a_content
 * @param a_flow_id
 * @param a_flow_caps
 * @return
 */
int avrs_content_flow_in_set_caps(avrs_content_t * a_content, uint8_t a_flow_id, const char * a_flow_caps )
{
    if( a_flow_id >= a_content->flows_count){
        log_it(L_WARNING, "Flow ID %u is too big (total count is %zd)", a_flow_id, a_content->flows_count);
        return -1;
    }
    GstAppSrc * l_app_src = PVT(a_content)->in.app_src[a_flow_id];
    assert( l_app_src);
    GstCaps * l_caps = gst_caps_from_string( a_flow_caps);
    if( !l_caps){
        log_it(L_WARNING, "Can't parse caps string \"%s\"", a_flow_caps);
        return -2;
    }
    gst_app_src_set_caps(l_app_src, l_caps);
    gst_object_unref(l_caps);
    return 0;
}

/**
 * @brief avrs_content_flow_out_get_caps
 * @param a_content
 * @param a_flow_id
 * @return Caps string
 */
char* avrs_content_flow_out_get_caps(avrs_content_t * a_content, uint8_t a_flow_id )
{
    if( a_flow_id >= a_content->flows_count){
        log_it(L_WARNING, "Flow ID %u is too big (total count is %zd)", a_flow_id, a_content->flows_count);
        return NULL;
    }
    GstAppSink * l_app_sink = PVT(a_content)->out.app_sink[a_flow_id];
    assert( l_app_sink);

    GstCaps * l_caps =gst_app_sink_get_caps(l_app_sink);
    if( !l_caps){
        log_it(L_WARNING, "Can't get caps from sink");
        return NULL;
    }
    char * l_ret = gst_caps_to_string(l_caps);
    gst_object_unref(l_caps);
    return l_ret;
}

/**
 * @brief The push_session_out struct
 */
struct push_session_out
{
    avrs_content_t * content;
    uint8_t flow_id;
    void * data;
    size_t data_size;

    // Iterate the push session out
    avrs_content_session_t * iter_content_session, *iter_tmp;
};

/**
 * @brief s_push_session_out_delete
 * @param a_args
 */
static void s_push_session_out_delete(struct push_session_out * a_args)
{
    assert(a_args);
    if(a_args->data)
        DAP_DELETE(a_args->data);
    DAP_DELETE(a_args);
}

/**
 * @brief avrs_content_data_push_session_out_inter
 * @param a_content
 * @param a_flow_id
 * @param a_data
 * @param a_data_size
 * @return
 */
int avrs_content_data_push_sessions_out_mt( avrs_content_t * a_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size)
{
int l_ret = 0;
struct push_session_out * l_args = DAP_NEW_Z(struct push_session_out);

    assert(l_args);

    l_args->data_size = a_data_size;
    l_args->data = DAP_DUP_SIZE(a_data,a_data_size);
    assert(l_args->data);

    l_args->content = a_content;
    l_args->flow_id = a_flow_id;

    if ( (l_ret = dap_events_socket_queue_ptr_send( s_queue_app_sink , l_args)) )
    {
        log_it(L_ERROR,"Can't push data to app sink queue, code %d", l_ret);
        s_push_session_out_delete(l_args);
    }

    return l_ret;
}

static void s_app_sink_callback_queue_ptr_iter(dap_worker_t * a_worker,void * a_arg)
{
    struct push_session_out * l_args = (struct push_session_out * ) a_arg;

    HASH_ITER(hh, l_args->content->sessions_out, l_args->iter_content_session, l_args->iter_tmp){
        avrs_content_session_t * l_content_session = l_args->iter_content_session;
        avrs_session_t * l_session = l_content_session->session;
        assert(l_session);
        dap_stream_ch_uuid_t l_avrs_ch_uuid = l_session->ch_uuid;
        dap_events_socket_t * l_es_input = DAP_STREAM_WORKER(a_worker)->queue_ch_io_input[l_session->ch_worker_id] ;
        avrs_ch_pkt_send_content_inter(l_es_input, l_avrs_ch_uuid, l_args->flow_id, l_content_session->content_session_id,
                                       l_args->data, l_args->data_size);
        // We break iterations by parts to not to overload the worker a lot
        dap_worker_exec_callback_on(a_worker,s_app_sink_callback_queue_ptr_iter, l_args );
        return;
    }
    // All iters passed through
    s_push_session_out_delete(l_args);
}

/**
 * @brief s_app_sink_callback_queue_ptr
 * @param a_es
 * @param a_arg
 */
static void s_app_sink_callback_queue_ptr(dap_events_socket_t * a_es, void * a_arg)
{
    s_app_sink_callback_queue_ptr_iter(a_es->worker, a_arg);
}

/**
 * @brief avrs_content_data_push
 * @param a_content
 * @param a_flow_id
 * @param a_data
 * @param a_data_size
 * @return
 */
int avrs_content_data_push_for_everyone_unsafe( avrs_content_t * a_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size)
{
    // Push GST input pipeline first;
    avrs_content_data_push_pipeline(a_content, a_flow_id, a_data, a_data_size);

    dap_context_t * l_context = dap_context_current();
    assert(l_context);
    dap_worker_t * l_worker = l_context->worker;
    assert(l_worker); // While we have no dap_context_ch or smth like this we do restream only from worker


    // Broadcast through all sessions
    avrs_content_session_t * l_content_session, *l_tmp;
    HASH_ITER(hh, a_content->sessions_out, l_content_session, l_tmp){
        avrs_session_t * l_session = l_content_session->session;
        assert(l_session);
        dap_stream_ch_uuid_t l_avrs_ch_uuid = l_session->ch_uuid;
        dap_events_socket_t * l_es_input = DAP_STREAM_WORKER(l_worker)->queue_ch_io_input[l_session->ch_worker_id] ;
        avrs_ch_pkt_send_content_inter(l_es_input, l_avrs_ch_uuid, a_flow_id, l_content_session->content_session_id, a_data, a_data_size);
    }

    return 0;
}


/**
 * @brief avrs_content_data_push_pipeline
 * @param a_content
 * @param a_flow_id
 * @param a_data
 * @param a_data_size
 * @return
 */
int avrs_content_data_push_pipeline( avrs_content_t * a_content, uint8_t a_flow_id, const void * a_data, size_t a_data_size)
{
    if( a_flow_id >= a_content->flows_count){
        log_it(L_WARNING, "Flow ID %u is too big (total count is %zd)", a_flow_id, a_content->flows_count);
        return -666;
    }

    // Process attached GST pipeline (if present)
    GstAppSrc * l_app_src = PVT(a_content)->in.app_src[a_flow_id];
    if(l_app_src){

        GstBuffer * l_buffer = NULL;    // @RRL gst_buffer_new_memdup(a_data,a_data_size);
        assert (l_buffer);

        GstFlowReturn l_ret = gst_app_src_push_buffer(l_app_src, l_buffer);
        gst_buffer_unref(l_buffer);
        if( l_ret != GST_FLOW_OK)
            return l_ret;
    }
    return 0;
}

/**
 * @brief Add session to the session out list for the target content
 * @param a_content
 * @param a_content_session_id
 * @param a_session
 * @return 0 if success, error code if not
 */
int avrs_content_add_session_out(avrs_content_t * a_content, uint32_t a_content_session_id, avrs_session_t * a_session)
{
avrs_content_session_t * l_content_session, *l_tmp;

    assert(a_content);
    assert(a_session);

    l_content_session = DAP_NEW_Z(avrs_content_session_t);              /* Preallocate memory for a new record */
    assert(l_content_session);

    // Check if its already present
    pthread_rwlock_wrlock( &a_content->rwlock);
    HASH_FIND(hh, a_content->sessions_out, &a_session->id, sizeof(a_session->id), l_tmp );
    if( !l_tmp )
        return  pthread_rwlock_unlock( &a_content->rwlock), DAP_DELETE(l_content_session), -ENOENT;

    l_content_session->content_session_id = a_content_session_id;
    l_content_session->session = a_session;
    l_content_session->session_id = a_session->id;

    HASH_ADD(hh, a_content->sessions_out, session_id, sizeof(l_content_session->session_id), l_content_session);
    pthread_rwlock_unlock( &a_content->rwlock);

    return 0;
}

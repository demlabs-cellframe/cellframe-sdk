#include <sys/socket.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_client.h"
#include "dap_client_remote.h"


#include "stream.h"
#include "stream_session.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_client.h"

#define LOG_TAG "dap_client"

/**
  * @brief Private data for sf_client
  */
typedef struct dap_client_pvt{
    dap_client_t * client;

    ev_io* w_client;
    struct sap_worker * worker;
    const char * a_name;

    dap_client_remote_t * stream_cr;
    dap_stream_t * stream;

    size_t stream_ch_size;
    dap_stream_ch_t ** ch; // Channels

    bool is_client_to_uplink;

    dap_stream_session_t * stream_session;
    dap_client_callback_t callback_connected;
    dap_client_callback_t callback_disconnected;
    dap_client_callback_t callback_error;
} dap_client_pvt_t;

#define DAP_CLIENT_PVT(a)  ( (dap_client_pvt_t *) ( a->_internal ) )

// Stage callbacks
void m_stage_status (dap_client_t * a_client, void* a_status);
void m_stage_stream_opened (dap_client_t * a_client, void* arg);
void m_stage_status_error (dap_client_t * a_client , void* a_error);

// Stream callbacks
void m_stream_cr_delete(dap_client_remote_t * a_cr, void * arg);
void m_stream_cr_read(dap_client_remote_t * a_cr, void * arg);
void m_stream_cr_write(dap_client_remote_t * a_cr, void * arg);
void m_stream_cr_error(dap_client_remote_t * a_cr, void * arg);



/**
 * @brief sf_client_new
 * @param a_events
 * @param a_worker
 * @param a_stream
 * @param a_name
 * @return
 */
static struct dap_events * s_events = NULL;
dap_client_t * dap_client_new(struct dap_events * a_events, const char * a_name,
                              const char * a_uplink_addr, uint16_t a_uplink_port)
{
    dap_client_t * l_ret = DAP_NEW_Z(dap_client_t);
    l_ret->_internal = DAP_NEW_Z(dap_client_pvt_t);
    dap_client_pvt_t * l_ret_pvt = DAP_CLIENT_PVT(l_ret);

    // Create SAP_CLIENT object and setup it with data from config
    l_ret_pvt->client = dap_client_new(m_stage_status,m_stage_status_error);
    l_ret_pvt->client->_inheritor = l_ret; // We inherit dap_client from dap_client_remote
    l_ret_pvt->events = a_events;
    s_events = a_events;

    dap_client_set_uplink(l_ret_pvt->client, a_uplink_addr, a_uplink_port);

    dap_client_go_stage(l_ret_pvt->client ,SAP_CLIENT_STAGE_STREAM_CTL ,m_stage_stream_opened );

    log_it(L_NOTICE,"Socket Forwarding client %s is initialized", l_pname );
    SAP_DELETE(l_pname);
    return l_ret;
}

/**
 * @brief sf_client_delete
 * @param a_client
 * @return
 */
int dap_client_delete(dap_client_t * a_client)
{

}

/**
 * @brief m_stage_stream_opened
 * @param a_client
 * @param arg
 */
void m_stage_stream_opened(sap_client_t * a_client, void* arg)
{
    log_it(L_INFO, "Stream session is opened, time to init it");

    dap_client_t * l_sf_client =  DAP_CLIENT(a_client);
    dap_client_pvt_t * l_sf_client_pvt = DAP_CLIENT_PVT(l_sf_client);
    l_sf_client_pvt->events = s_events;
    if(l_sf_client == NULL ){
        log_it(L_ERROR, "sap_client is not inisialized");
        return;
    }

    int l_sock_peer = socket(PF_INET,SOCK_STREAM,0);

    if( l_sock_peer < 1 ){
        log_it(L_ERROR,"Can't create the socket: %s", strerror(errno) );
        return;
    }

//    fcntl(l_sock_peer, F_SETFL, O_NONBLOCK);
    setsockopt(l_sock_peer,SOL_SOCKET,SO_SNDBUF,(const void*) 20000000,sizeof(int) );
    setsockopt(l_sock_peer,SOL_SOCKET,SO_RCVBUF,(const void *) 10000000,sizeof(int) );

    // Wrap socket and setup callbacks
    static sap_events_socket_callbacks_t l_s_callbacks={
        .read_callback = m_stream_cr_read ,
        .write_callback = m_stream_cr_write ,
        .error_callback = m_stream_cr_error ,
        .delete_callback = m_stream_cr_delete
    };



    l_sf_client_pvt->stream_cr = sap_events_socket_wrap_no_add(l_sf_client_pvt->events,
                           l_sock_peer, &l_s_callbacks);

    l_sf_client_pvt->stream_cr->_inheritor = l_sf_client; // Inherit SF_CLIENT object to stream (then proxy to stream_ch objects)
    l_sf_client_pvt->stream = sap_stream_new_es(l_sf_client_pvt->stream_cr);
    l_sf_client_pvt->stream->is_client_to_uplink = true;
    l_sf_client_pvt->stream_session = sap_stream_session_pure_new();

    l_sf_client_pvt->stream_session->opened = true;
    l_sf_client_pvt->stream_session->is_client_to_uplink = true;
    l_sf_client_pvt->stream_session->key = sap_client_get_key_stream(a_client);
    l_sf_client_pvt->stream->session =  l_sf_client_pvt->stream_session;// Connect to session object created before
    l_sf_client_pvt->stream_ch_sf = sap_stream_ch_new( l_sf_client_pvt->stream ,'s' );
    l_sf_client_pvt->ch_sf = CH_SF(l_sf_client_pvt->stream_ch_sf);
    sap_stream_es_rw_states_update( l_sf_client_pvt->stream );
    sap_events_socket_set_readable( l_sf_client_pvt->stream_cr,true );

    sap_events_socket_create_after(l_sf_client_pvt->stream_cr);
    // Compose URL
    size_t l_url_size_max = 1024;
    char * l_url = SAP_NEW_Z_SIZE(char,l_url_size_max);
    size_t l_url_size = snprintf(l_url,l_url_size_max,"/%s/fjskd9234j?fj913htmdgaq-d9hf=%s", SAP_UPLINK_PATH_STREAM,
             sap_client_get_stream_id(a_client) );

    // Compose HTTP request
    size_t l_request_size_max = 4096;
    char * l_request = SAP_NEW_Z_SIZE(char,l_request_size_max);
    size_t l_request_size = snprintf(l_request, l_request_size_max,
                                     "POST %s HTTP/1.1\r\n"
                                     "Connection: Keep-Alive\r\n"
                                     "Cookie: %s\r\n"
                                     "User-Agent: libsap \r\n"
                                     "Host: %3\r\n"
                                     "\r\n",
                                     l_url, sap_client_get_auth_cookie(a_client),
                                     sap_client_get_uplink_addr(a_client)
                              );

    // Configure remote address
    struct sockaddr_in l_remote_addr;
    l_remote_addr.sin_addr.s_addr = inet_addr( sap_client_get_uplink_addr(a_client) );
    l_remote_addr.sin_family = AF_INET;
    l_remote_addr.sin_port = htons( sap_client_get_uplink_port(a_client) );
    log_it(L_INFO, "Prepared request, connecting to the uplink...");
    if( connect(l_sock_peer , (struct sockaddr *)&l_remote_addr , sizeof(l_remote_addr) ) == 0 ){
        log_it(L_NOTICE, "Connected to the uplink");
        send(l_sock_peer,l_request,l_request_size,0);
        SAP_DELETE(l_request);
    }
}

/**
 * @brief m_es_stream_delete
 * @param a_es
 * @param arg
 */
void m_stream_cr_delete(sap_events_socket_t * a_es, void * arg)
{
    log_it(L_INFO, "Reconnecting peer");
    dap_client_t * l_client = DAP_CLIENT(a_es);
    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(l_client);
    sap_stream_delete(l_client_pvt->stream);
    l_client_pvt->stream = NULL;
    if(l_client_pvt->client)
        sap_client_reset(l_client_pvt->client);
    l_client_pvt->ch_sf = NULL;
    l_client_pvt->stream_ch_sf = NULL;
    l_client_pvt->stream_cr = NULL;
    sap_stream_session_close(l_client_pvt->stream_session->id);
    l_client_pvt->stream_session = NULL;
    sap_client_go_stage(l_client_pvt->client ,SAP_CLIENT_STAGE_STREAM_CTL ,m_stage_stream_opened );
}

/**
 * @brief m_es_stream_read
 * @param a_es
 * @param arg
 */
void m_stream_cr_read(sap_events_socket_t * a_es, void * arg)
{
    dap_client_t * l_client = DAP_CLIENT(a_es);
    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(l_client);
    switch( l_client->stage ){
        case DAP_CLIENT_DISCONNECTED: l_client->stage = DAP_CLIENT_CONNECTING;
        case DAP_CLIENT_CONNECTING:{
            l_client->stage = DAP_CLIENT_CONNECTED_HTTP_HEADERS;
        }
        case DAP_CLIENT_CONNECTED_HTTP_HEADERS:{
            if(a_es->buf_in_size>1){
                char * p;
                p = (char*) memchr( a_es->buf_in,'\r',a_es->buf_in_size-1);
                if ( p ){
                    if (  *(p+1) == '\n'  ) {
                        sap_events_socket_shrink_buf_in(a_es,p - a_es->buf_in_str );
                        log_it(L_DEBUG,"Header passed, go to streaming (%lu bytes already are in input buffer", a_es->buf_in_size);
                        l_client->stage = DAP_CLIENT_CONNECTED_STREAMING;
                        sap_stream_data_proc_read(l_client_pvt->stream);
                        sap_events_socket_shrink_buf_in(a_es,a_es->buf_in_size );


                        pthread_mutex_lock(&m_tun_server->clients_mutex);
                        ch_sf_pkt_t * l_sf_pkt ;
                        size_t l_sf_pkt_data_size = sizeof(in_addr_t)*2*(m_tun_server->peers_count+1);
                        size_t l_sf_pkt_size = sizeof(l_sf_pkt->header)+l_sf_pkt_data_size;
                        size_t i;
                        l_sf_pkt = SAP_NEW_Z_SIZE(ch_sf_pkt_t,l_sf_pkt_size);
                        l_sf_pkt->header.op_code = STREAM_SF_PACKET_OP_CODE_L3_ADDR_REQUEST;
                        l_sf_pkt->header.op_data.data_size = l_sf_pkt_data_size;
                        memcpy(l_sf_pkt->data,
                               &m_tun_server->int_network,sizeof(m_tun_server->int_network));
                        memcpy(l_sf_pkt->data+sizeof(in_addr_t),
                               &m_tun_server->int_network_mask,sizeof(m_tun_server->int_network_mask));

                        for(i=1; i< m_tun_server->peers_count+1; i++){
                            memcpy(l_sf_pkt->data+i*sizeof(in_addr_t)*2,
                                   &m_tun_server->peers[i].netaddr,sizeof(in_addr_t));
                            memcpy(l_sf_pkt->data+i*sizeof(in_addr_t)*2+sizeof(in_addr_t),
                                   &m_tun_server->peers[i].netmask,sizeof(in_addr_t));
                            log_it(L_NOTICE, "Add netaddr %s in request", m_tun_server->peers[i].netaddr);
                        }

                        pthread_mutex_unlock(&m_tun_server->clients_mutex);
                        log_it(L_NOTICE, "Send L3 address request");
                        stream_ch_pkt_write(l_client_pvt->stream_ch_sf,'d',l_sf_pkt,l_sf_pkt_size );
                        SAP_DELETE(l_sf_pkt);
                    }
                }
            }
        }break;
        case DAP_CLIENT_CONNECTED_STREAMING:{
            sap_stream_data_proc_read(l_client_pvt->stream);
            sap_events_socket_shrink_buf_in(a_es,a_es->buf_in_size );
        }
    }
}

/**
 * @brief m_es_stream_write
 * @param a_es
 * @param arg
 */
void m_stream_cr_write(sap_events_socket_t * a_es, void * arg)
{
    dap_client_t * l_client = DAP_CLIENT(a_es);
    switch( l_client->stage ){
        case DAP_CLIENT_DISCONNECTED: l_client->stage = DAP_CLIENT_CONNECTING;
        case DAP_CLIENT_CONNECTING:{
            l_client->stage = DAP_CLIENT_CONNECTED_HTTP_HEADERS;
        }break;
        case DAP_CLIENT_CONNECTED_STREAMING:{
            size_t i;
            bool ready_to_write=false;
          //  log_it(DEBUG,"Process channels data output (%u channels)",STREAM(sh)->channel_count);

            for(i=0;i< DAP_CLIENT_PVT(l_client)->stream->channel_count; i++){
                sap_stream_ch_t * ch = DAP_CLIENT_PVT(l_client)->stream->channel[i];
                if(ch->writable){
                    ch->proc->packet_out_callback(ch,NULL);
                    ready_to_write|=ch->writable;
                }
            }
            //log_it(L_DEBUG,"stream_data_out (ready_to_write=%s)", ready_to_write?"true":"false");

            sap_events_socket_set_writable(DAP_CLIENT_PVT(l_client)->stream_cr,ready_to_write);
            //log_it(ERROR,"No stream_data_write_callback is defined");
        }break;
    }
}

/**
 * @brief m_es_stream_error
 * @param a_es
 * @param arg
 */
void m_stream_cr_error(sap_events_socket_t * a_es, void * arg)
{
    dap_client_t * l_client = DAP_CLIENT(a_es);
    log_it(L_ERROR,"ES stream error");
}




/**
 * @brief m_stage_status
 * @param a_client
 * @param a_status
 */
void m_stage_status (sap_client_t * a_client, void* a_status)
{

}

/**
 * @brief m_stage_status_error
 * @param a_client
 * @param a_error
 */
void m_stage_status_error (sap_client_t * a_client , void* a_error)
{

}

/**
 * @brief sf_client_set_callback_error
 * @param a_client
 * @param a_client_callback_error
 */
void dap_client_set_callback_error(dap_client_t * a_client, dap_client_callback_t a_client_callback_error)
{
    DAP_CLIENT_PVT(a_client)->callback_error = a_client_callback_error;
}

/**
 * @brief sf_client_set_callback_connected
 * @param a_client
 * @param a_client_callback_connected
 */
void dap_client_set_callback_connected(dap_client_t * a_client, dap_client_callback_t a_client_callback_connected)
{
    DAP_CLIENT_PVT(a_client)->callback_connected = a_client_callback_connected;
}

/**
 * @brief sf_client_set_callback_disconnected
 * @param a_client
 * @param a_client_callback_disconnected
 */
void dap_client_set_callback_disconnected(dap_client_t * a_client, dap_client_callback_t a_client_callback_disconnected)
{
    DAP_CLIENT_PVT(a_client)->callback_disconnected = a_client_callback_disconnected;
}

/**
 * @brief sf_client_get_addr
 * @param a_client
 * @return
 */
struct in_addr sf_client_get_addr(dap_client_t * a_client)
{
    return DAP_CLIENT_PVT(a_client)->stream_session->tun_client_addr;
}

/**
 * @brief sf_client_get_gw
 * @param a_client
 * @return
 */
struct in_addr sf_client_get_gw(dap_client_t * a_client)
{
    return DAP_CLIENT_PVT(a_client)->stream_session->tun_client_gw;
}

/**
 * @brief sf_client_get_netmask
 * @param a_client
 * @return
 */
struct in_addr sf_client_get_netmask(dap_client_t * a_client)
{
    return DAP_CLIENT_PVT(a_client)->stream_session->tun_client_mask;
}
